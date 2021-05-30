// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Concurrent;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.Asn1;
using System.Threading.Tasks;
using Kerberos.NET.Entities;
using Kerberos.NET.Transport;
using Microsoft.Extensions.Logging;
using MessageHandlerConstructor = System.Func<System.ReadOnlyMemory<byte>, Kerberos.NET.Server.KdcServerOptions, Kerberos.NET.Server.KdcMessageHandlerBase>;
using PreAuthHandlerConstructor = System.Func<Kerberos.NET.Server.IRealmService, Kerberos.NET.Server.KdcPreAuthenticationHandlerBase>;

namespace Kerberos.NET.Server
{
    public class KdcServer
    {
        private readonly KdcServerOptions options;

        private readonly ILogger<KdcServer> logger;

        public KdcServer(KdcServerOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            this.options = options;
            this.logger = options.Log.CreateLoggerSafe<KdcServer>();

            if (options.Configuration.KdcDefaults.RegisterDefaultAsReqHandler)
            {
                this.RegisterMessageHandler(MessageType.KRB_AS_REQ, (message, op) => new KdcAsReqMessageHandler(message, op));
                this.RegisterPreAuthHandler(PaDataType.PA_ENC_TIMESTAMP, (service) => new PaDataTimestampHandler(service));

                if (options.Configuration.KdcDefaults.RegisterDefaultPkInitPreAuthHandler)
                {
                    this.RegisterPreAuthHandler(PaDataType.PA_PK_AS_REQ, (service) => new PaDataPkAsReqHandler(service));
                }
            }

            if (options.Configuration.KdcDefaults.RegisterDefaultTgsReqHandler)
            {
                this.RegisterMessageHandler(MessageType.KRB_TGS_REQ, (message, op) => new KdcTgsReqMessageHandler(message, op));
            }
        }

        private readonly ConcurrentDictionary<MessageType, MessageHandlerConstructor> messageHandlers =
            new ConcurrentDictionary<MessageType, MessageHandlerConstructor>();

        private readonly ConcurrentDictionary<PaDataType, PreAuthHandlerConstructor> preAuthHandlers =
            new ConcurrentDictionary<PaDataType, PreAuthHandlerConstructor>();

        public void RegisterMessageHandler(MessageType type, MessageHandlerConstructor builder)
        {
            ValidateSupportedMessageType(type);

            this.messageHandlers[type] = builder;
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
            this.preAuthHandlers[type] = builder;
        }

        public async Task<ReadOnlyMemory<byte>> ProcessMessage(ReadOnlyMemory<byte> request)
        {
            // This should probably only process AS-REQs and TGS-REQs
            // Everything else should fail miserably with an error
            // But we'll leave it to the registered handlers to decide
            // what they are willing to process

            // but we also need to process Kdc Proxy messages

            var tag = KrbMessage.PeekTag(request);

            if (tag == Asn1Tag.Sequence && this.options.Configuration.KdcDefaults.ProxyEnabled)
            {
                try
                {
                    return await this.ProcessProxyMessageAsync(request).ConfigureAwait(false);
                }
                catch (Exception ex) when (IsProtocolException(ex))
                {
                    this.logger.LogWarning(ex, "Proxy message could not be parsed correctly");

                    return KdcMessageHandlerBase.GenerateGenericError(ex, this.options);
                }
            }

            return await this.ProcessMessageCoreAsync(request, tag).ConfigureAwait(false);
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
                messageHandler = this.LocateMessageHandler(request, tag);
            }
            catch (Exception ex) when (IsProtocolException(ex))
            {
                this.logger.LogWarning(ex, "Message handler could not be located for message");

                return KdcMessageHandlerBase.GenerateGenericError(ex, this.options);
            }

            try
            {
                return await messageHandler.ExecuteAsync().ConfigureAwait(false);
            }
            catch (Exception ex) when (IsProtocolException(ex))
            {
                this.logger.LogWarning(ex, "Message handler {MessageHandler} could not process message", messageHandler.GetType());

                return KdcMessageHandlerBase.GenerateGenericError(ex, this.options);
            }
        }

        private KdcMessageHandlerBase LocateMessageHandler(ReadOnlyMemory<byte> request, Asn1Tag tag)
        {
            MessageType messageType = KrbMessage.DetectMessageType(tag);

            ValidateSupportedMessageType(messageType);

            if (!this.messageHandlers.TryGetValue(messageType, out MessageHandlerConstructor builder))
            {
                throw new KerberosProtocolException(
                    KerberosErrorCode.KRB_ERR_GENERIC,
                    $"Application tag {messageType} doesn't have a message handler registered"
                );
            }

            var handler = builder(request, this.options);

            if (handler == null)
            {
                throw new InvalidOperationException($"Message handler builder {messageType} must not return null");
            }

            handler.RegisterPreAuthHandlers(this.preAuthHandlers);

            return handler;
        }

        private async Task<ReadOnlyMemory<byte>> ProcessProxyMessageAsync(ReadOnlyMemory<byte> request)
        {
            var proxyMessage = KdcProxyMessage.Decode(request);

            var unwrapped = proxyMessage.UnwrapMessage(out KdcProxyMessageMode mode);

            var tag = KrbMessage.PeekTag(unwrapped);

            var response = await this.ProcessMessageCoreAsync(unwrapped, tag).ConfigureAwait(false);

            return EncodeProxyResponse(response, mode);
        }

        private static ReadOnlyMemory<byte> EncodeProxyResponse(ReadOnlyMemory<byte> response, KdcProxyMessageMode mode)
        {
            return KdcProxyMessage.WrapMessage(response, mode: mode).Encode();
        }
    }
}
