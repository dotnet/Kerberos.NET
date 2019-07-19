using Kerberos.NET.Dns;
using System;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace Kerberos.NET.Transport
{
    internal class UdpKerberosTransport : KerberosTransportBase
    {
        private const string UdpServiceTemplate = "_kerberos._udp.{0}";

        public override bool TransportFailed { get; set; }

        public override KerberosTransportException LastError { get; set; }

        public UdpKerberosTransport(string kdc = null)
            : base(kdc)
        {
        }

        public override async Task<T> SendMessage<T>(string domain, ReadOnlyMemory<byte> encoded)
        {
            var target = LocateKdc(domain);

            using (var client = new UdpClient(target.Target, target.Port))
            {
                Log($"UDP connecting to {target.Target}");

                var result = await client.SendAsync(encoded.ToArray(), encoded.Length);

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
