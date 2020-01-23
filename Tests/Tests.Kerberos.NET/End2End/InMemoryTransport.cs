using System;
using System.Threading;
using System.Threading.Tasks;
using Kerberos.NET.Transport;

namespace Tests.Kerberos.NET
{
    internal class InMemoryTransport : KerberosTransportBase
    {
        private readonly KdcListener listener;

        public InMemoryTransport(KdcListener listener)
        {
            this.listener = listener;
            this.Enabled = true;
        }

        public override async Task<T> SendMessage<T>(
            string domain, 
            ReadOnlyMemory<byte> req, 
            CancellationToken cancellation = default
        )
        {
            var response = await listener.Receive(req);

            return Decode<T>(response);
        }
    }
}