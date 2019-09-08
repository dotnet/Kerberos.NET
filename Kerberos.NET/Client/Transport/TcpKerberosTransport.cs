using Kerberos.NET.Asn1;
using Kerberos.NET.Crypto;
using Kerberos.NET.Dns;
using System;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace Kerberos.NET.Transport
{
    public class TcpKerberosTransport : KerberosTransportBase
    {
        private const string TcpServiceTemplate = "_kerberos._tcp.{0}";

        public TcpKerberosTransport(string kdc = null)
            : base(kdc)
        {
            Enabled = true;
        }

        public override ProtocolType Protocol => ProtocolType.Tcp;

        public override async Task<T> SendMessage<T>(string domain, ReadOnlyMemory<byte> encoded)
        {
            var target = LocateKdc(domain);

            Log($"TCP connecting to {target.Target}");

            using (var client = new TcpClient(AddressFamily.InterNetwork))
            {
                client.LingerState = new LingerOption(false, 0);

                try
                {
                    await client.ConnectAsync(target.Target, target.Port);
                }
                catch (SocketException sx)
                {
                    throw new KerberosTransportException("TCP Connect failed", sx);
                }

                var stream = client.GetStream();

                var messageSize = new Memory<byte>(new byte[4]);
                Endian.ConvertToBigEndian(encoded.Length, messageSize);

                await stream.WriteAsync(messageSize);
                await stream.WriteAsync(encoded);
                await stream.FlushAsync();

                await stream.ReadAsync(messageSize.Slice(0, 4));

                var response = new byte[messageSize.Span.AsLong()];

                await stream.FlushAsync();
                await stream.ReadAsync(response);

                return Decode<T>(response);
            }
        }

        protected DnsRecord LocateKdc(string domain)
        {
            var lookup = string.Format(TcpServiceTemplate, domain);

            return QueryDomain(lookup);
        }
    }
}
