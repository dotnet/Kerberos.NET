using Kerberos.NET.Dns;
using System;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Kerberos.NET.Transport
{
    public class UdpKerberosTransport : KerberosTransportBase
    {
        private const string UdpServiceTemplate = "_kerberos._udp.{0}";

        public override bool TransportFailed { get; set; }

        public override KerberosTransportException LastError { get; set; }

        public UdpKerberosTransport(string kdc = null)
            : base(kdc)
        {
            Enabled = false;
        }

        public override async Task<T> SendMessage<T>(
            string domain,
            ReadOnlyMemory<byte> encoded,
            CancellationToken cancellation = default
        )
        {
            var target = LocateKdc(domain);

            using (var client = new UdpClient(target.Target, target.Port))
            {
                cancellation.ThrowIfCancellationRequested();

                var result = await client.SendAsync(encoded.ToArray(), encoded.Length);

                cancellation.ThrowIfCancellationRequested();

                var response = await client.ReceiveAsync();

                return Decode<T>(response.Buffer);
            }
        }

        protected DnsRecord LocateKdc(string domain)
        {
            var lookup = string.Format(UdpServiceTemplate, domain);

            return QueryDomain(lookup);
        }
    }
}
