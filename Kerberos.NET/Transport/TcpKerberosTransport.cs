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

        public override async Task<T> SendMessage<T>(string domain, ReadOnlyMemory<byte> encoded)
        {
            var target = LocateKdc(domain);

            Log($"TCP connecting to {target.Target}");

            using (var client = new TcpClient(AddressFamily.InterNetwork))
            {
                try
                {
                    await client.ConnectAsync(target.Target, target.Port);
                }
                catch (SocketException sx)
                {
                    throw new KerberosTransportException("TCP Connect failed", sx);
                }

                var stream = client.GetStream();

                var messageSize = new byte[4];
                Endian.ConvertToBigEndian(encoded.Length, messageSize, 0);

                await stream.WriteAsync(messageSize);
                await stream.WriteAsync(encoded);
                await stream.FlushAsync();

                await stream.ReadAsync(messageSize, 0, 4);

                var response = new byte[messageSize.AsLong()];

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
