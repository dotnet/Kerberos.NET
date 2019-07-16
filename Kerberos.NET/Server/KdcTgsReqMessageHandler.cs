using Kerberos.NET.Entities;
using System;
using System.Buffers;
using System.Threading.Tasks;

namespace Kerberos.NET.Server
{
    internal class KdcTgsReqMessageHandler : KdcMessageHandlerBase
    {
        public KdcTgsReqMessageHandler(ReadOnlySequence<byte> message, KdcListenerOptions options) 
            : base(message, options)
        {
        }

        protected override async Task<ReadOnlyMemory<byte>> ExecuteCore(ReadOnlyMemory<byte> message)
        {
            var tgsReqMessage = KrbTgsReq.DecodeMessageAsApplication(message);

            var tgsReq = tgsReqMessage.TgsReq;

            await SetRealmContext(tgsReq.Body.Realm);


            throw new NotImplementedException();
        }
    }
}