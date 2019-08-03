using Kerberos.NET.Entities;
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

        public KdcServer(ListenerOptions options)
        {
            this.options = options;

            RegisterMessageHandler(MessageType.KRB_AS_REQ, (message, op) => new KdcAsReqMessageHandler(message, op));
            RegisterMessageHandler(MessageType.KRB_TGS_REQ, (message, op) => new KdcTgsReqMessageHandler(message, op));

            RegisterPreAuthHandler(PaDataType.PA_ENC_TIMESTAMP, (service) => new PaDataTimestampHandler(service));
        }

        private readonly ConcurrentDictionary<MessageType, MessageHandlerConstructor> messageHandlers =
            new ConcurrentDictionary<MessageType, MessageHandlerConstructor>();

        private readonly ConcurrentDictionary<PaDataType, PreAuthHandlerConstructor> preAuthHandlers =
            new ConcurrentDictionary<PaDataType, PreAuthHandlerConstructor>();

        public void RegisterMessageHandler(MessageType type, MessageHandlerConstructor builder)
        {
            if (type < MessageType.KRB_AS_REQ || type > MessageType.KRB_ERROR)
            {
                throw new InvalidOperationException($"Cannot register {type}. Can only register application messages >= 10 and <= 30");
            }

            messageHandlers[type] = builder;
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

            KdcMessageHandlerBase messageHandler;

            try
            {
                messageHandler = LocateMessageHandler(request);

                return await messageHandler.Execute();
            }
            catch (Exception ex)
            {
                Log(ex);

                return KdcMessageHandlerBase.GenerateGenericError(ex, options);
            }
        }

        private KdcMessageHandlerBase LocateMessageHandler(ReadOnlySequence<byte> request)
        {
            Asn1Tag tag = PeekTag(request);

            if (tag.TagClass != TagClass.Application)
            {
                throw new KerberosProtocolException($"Unknown incoming tag {tag}");
            }

            var messageType = (MessageType)tag.TagValue;

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

        private static Asn1Tag PeekTag(ReadOnlySequence<byte> request)
        {
            AsnReader reader = new AsnReader(request.ToArray(), AsnEncodingRules.DER);

            return reader.PeekTag();
        }

        private void Log(Exception ex)
        {
            options?.Log?.WriteLine(KerberosLogSource.Kdc, ex);
        }
    }
}
