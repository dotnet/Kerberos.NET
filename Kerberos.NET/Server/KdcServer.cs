using System;
using System.Collections.Concurrent;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.Asn1;
using System.Threading.Tasks;
using Kerberos.NET.Entities;
using Kerberos.NET.Transport;
using Microsoft.Extensions.Logging;

namespace Kerberos.NET.Server
{
    using MessageHandlerConstructor = Func<ReadOnlyMemory<byte>, ListenerOptions, KdcMessageHandlerBase>;
    using PreAuthHandlerConstructor = Func<IRealmService, KdcPreAuthenticationHandlerBase>;

    public class KdcServer
    {
        private readonly ListenerOptions options;

        private readonly ILogger<KdcServer> logger;

        public KdcServer(ListenerOptions options)
        {
            this.options = options;
            this.logger = options.Log.CreateLoggerSafe<KdcServer>();

            if (options.RegisterDefaultAsReqHandler)
            {
                RegisterMessageHandler(MessageType.KRB_AS_REQ, (message, op) => new KdcAsReqMessageHandler(message, op));
                RegisterPreAuthHandler(PaDataType.PA_ENC_TIMESTAMP, (service) => new PaDataTimestampHandler(service));

                if (options.RegisterDefaultPkInitPreAuthHandler)
                {
                    RegisterPreAuthHandler(PaDataType.PA_PK_AS_REQ, (service) => new PaDataPkAsReqHandler(service));
                }
            }

            if (options.RegisterDefaultTgsReqHandler)
            {
                RegisterMessageHandler(MessageType.KRB_TGS_REQ, (message, op) => new KdcTgsReqMessageHandler(message, op));
            }
        }

        private readonly ConcurrentDictionary<MessageType, MessageHandlerConstructor> messageHandlers =
            new ConcurrentDictionary<MessageType, MessageHandlerConstructor>();

        private readonly ConcurrentDictionary<PaDataType, PreAuthHandlerConstructor> preAuthHandlers =
            new ConcurrentDictionary<PaDataType, PreAuthHandlerConstructor>();

        public void RegisterMessageHandler(MessageType type, MessageHandlerConstructor builder)
        {
            ValidateSupportedMessageType(type);

            messageHandlers[type] = builder;
        }

        private static void ValidateSupportedMessageType(MessageType type)
        {
            if (!type.IsValidMessageType())
            {
                throw new InvalidOperationException(
                    $"Cannot register {type}. Can only register application messages >= 10 and <= 30"
                );
            }
        }

        public void RegisterPreAuthHandler(PaDataType type, PreAuthHandlerConstructor builder)
        {
            preAuthHandlers[type] = builder;
        }

        public async Task<ReadOnlyMemory<byte>> ProcessMessage(ReadOnlyMemory<byte> request)
        {
            // This should probably only process AS-REQs and TGS-REQs
            // Everything else should fail miserably with an error
            // But we'll leave it to the registered handlers to decide
            // what they are willing to process

            // but we also need to process Kdc Proxy messages

            var tag = KrbMessage.PeekTag(request);

            if (tag == Asn1Tag.Sequence && options.ProxyEnabled)
            {
                try
                {
                    return await ProcessProxyMessageAsync(request);
                }
                catch (Exception ex) when (IsProtocolException(ex))
                {
                    logger.LogWarning(ex, "Proxy message could not be parsed correctly");

                    return KdcMessageHandlerBase.GenerateGenericError(ex, options);
                }
            }

            return await ProcessMessageCoreAsync(request, tag);
        }

        private static bool IsProtocolException(Exception ex)
        {
            // These checks should only apply when you're trying to return a graceful 
            // failure to the client with a krb-error and a generic error message

            // All other failures should be handled by the caller

            if (ex is KerberosProtocolException || ex is KerberosValidationException || ex is KerberosTransportException)
            {
                return true;
            }

            if (ex is CryptographicException || ex is SecurityException)
            {
                return true;
            }

            if (ex is ArgumentException || ex is ArgumentNullException || ex is InvalidOperationException)
            {
                return true;
            }

            return false;
        }

        internal virtual async Task<ReadOnlyMemory<byte>> ProcessMessageCoreAsync(ReadOnlyMemory<byte> request, Asn1Tag tag)
        {
            KdcMessageHandlerBase messageHandler;

            try
            {
                messageHandler = LocateMessageHandler(request, tag);
            }
            catch (Exception ex) when (IsProtocolException(ex))
            {
                logger.LogWarning(ex, "Message handler could not be located for message");

                return KdcMessageHandlerBase.GenerateGenericError(ex, options);
            }

            try
            {
                return await messageHandler.ExecuteAsync();
            }
            catch (Exception ex) when (IsProtocolException(ex))
            {
                logger.LogWarning(ex, "Message handler {MessageHandler} could not process message", messageHandler.GetType());

                return KdcMessageHandlerBase.GenerateGenericError(ex, options);
            }
        }

        private KdcMessageHandlerBase LocateMessageHandler(ReadOnlyMemory<byte> request, Asn1Tag tag)
        {
            MessageType messageType = KrbMessage.DetectMessageType(tag);

            ValidateSupportedMessageType(messageType);

            if (!messageHandlers.TryGetValue(messageType, out MessageHandlerConstructor builder))
            {
                throw new KerberosProtocolException(
                    KerberosErrorCode.KRB_ERR_GENERIC,
                    $"Application tag {messageType} doesn't have a message handler registered"
                );
            }

            var handler = builder(request, options);

            if (handler == null)
            {
                throw new InvalidOperationException($"Message handler builder {messageType} must not return null");
            }

            handler.RegisterPreAuthHandlers(preAuthHandlers);

            return handler;
        }

        private async Task<ReadOnlyMemory<byte>> ProcessProxyMessageAsync(ReadOnlyMemory<byte> request)
        {
            var proxyMessage = KdcProxyMessage.Decode(request);

            var unwrapped = proxyMessage.UnwrapMessage(out KdcProxyMessageMode mode);

            var tag = KrbMessage.PeekTag(unwrapped);

            var response = await ProcessMessageCoreAsync(unwrapped, tag);

            return EncodeProxyResponse(response, mode);
        }

        private static ReadOnlyMemory<byte> EncodeProxyResponse(ReadOnlyMemory<byte> response, KdcProxyMessageMode mode)
        {
            return KdcProxyMessage.WrapMessage(response, mode: mode).Encode();
        }
    }
}
