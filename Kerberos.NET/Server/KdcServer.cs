using Kerberos.NET.Entities;
using Microsoft.Extensions.Logging;
using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Security.Cryptography.Asn1;
using System.Threading.Tasks;

namespace Kerberos.NET.Server
{
    using MessageHandlerConstructor = Func<ReadOnlySequence<byte>, ListenerOptions, KdcMessageHandlerBase>;
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
            if (type < MessageType.KRB_AS_REQ || type > MessageType.KRB_ERROR)
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

        public async Task<ReadOnlyMemory<byte>> ProcessMessage(ReadOnlySequence<byte> request)
        {
            // This should probably only process AS-REQs and TGS-REQs
            // Everything else should fail miserably with an error
            // But we'll leave it to the registered handlers to decide
            // what they are willing to process

            // but we also need to process Kdc Proxy messages

            var tag = PeekTag(request.First);

            if (tag == Asn1Tag.Sequence && options.ProxyEnabled)
            {
                try
                {
                    return await ProcessProxyMessage(request);
                }
                catch (Exception ex)
                {
                    logger.LogWarning(ex, "Proxy message could not be parsed correctly");

                    return KdcMessageHandlerBase.GenerateGenericError(ex, options);
                }
            }

            return await ProcessMessageCore(request, tag);
        }

        internal virtual async Task<ReadOnlyMemory<byte>> ProcessMessageCore(ReadOnlySequence<byte> request, Asn1Tag tag)
        {
            KdcMessageHandlerBase messageHandler;

            try
            {
                messageHandler = LocateMessageHandler(request, tag);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Message handler could not be located for message");

                return KdcMessageHandlerBase.GenerateGenericError(ex, options);
            }

            try
            {
                return await messageHandler.Execute();
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Message handler {MessageHandler} could not process message", messageHandler.GetType());

                return KdcMessageHandlerBase.GenerateGenericError(ex, options);
            }
        }

        private KdcMessageHandlerBase LocateMessageHandler(ReadOnlySequence<byte> request, Asn1Tag tag)
        {
            MessageType messageType = DetectMessageType(tag);

            if (!messageHandlers.TryGetValue(messageType, out MessageHandlerConstructor builder))
            {
                throw new KerberosProtocolException($"Application tag {messageType} doesn't have a message handler registered");
            }

            var handler = builder(request, options);

            if (handler == null)
            {
                throw new InvalidOperationException($"Message handler builder {messageType} must not return null");
            }

            handler.RegisterPreAuthHandlers(preAuthHandlers);

            return handler;
        }

        public static MessageType DetectMessageType(ReadOnlyMemory<byte> message)
        {
            var tag = PeekTag(message);

            return DetectMessageType(tag);
        }

        private static MessageType DetectMessageType(Asn1Tag tag)
        {
            if (tag.TagClass != TagClass.Application)
            {
                throw new KerberosProtocolException($"Unknown incoming tag {tag}");
            }

            var messageType = (MessageType)tag.TagValue;

            ValidateSupportedMessageType(messageType);

            return messageType;
        }

        private async Task<ReadOnlyMemory<byte>> ProcessProxyMessage(ReadOnlySequence<byte> request)
        {
            var proxyMessage = KdcProxyMessage.Decode(request.ToArray());

            var unwrapped = proxyMessage.UnwrapMessage();

            var tag = PeekTag(unwrapped);

            var response = await ProcessMessageCore(new ReadOnlySequence<byte>(unwrapped), tag);

            return EncodeProxyResponse(response);
        }

        private static ReadOnlyMemory<byte> EncodeProxyResponse(ReadOnlyMemory<byte> response)
        {
            return KdcProxyMessage.WrapMessage(response).Encode();
        }

        private static Asn1Tag PeekTag(ReadOnlyMemory<byte> request)
        {
            AsnReader reader = new AsnReader(request, AsnEncodingRules.DER);

            return reader.PeekTag();
        }
    }
}
