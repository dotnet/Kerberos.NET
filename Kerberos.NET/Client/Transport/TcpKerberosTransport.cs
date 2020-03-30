using System;
using System.Buffers.Binary;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Kerberos.NET.Dns;
using Microsoft.Extensions.Logging;

namespace Kerberos.NET.Transport
{
    public class TcpKerberosTransport : KerberosTransportBase
    {
        private const string TcpServiceTemplate = "_kerberos._tcp.{0}";

        private static readonly ISocketPool pool = CreateSocketPool();

        private readonly ILogger<TcpKerberosTransport> logger;

        public TcpKerberosTransport(ILoggerFactory logger, string kdc = null)
            : base(kdc)
        {
            this.logger = logger.CreateLoggerSafe<TcpKerberosTransport>();

            Enabled = true;
        }

        public static int MaxPoolSize
        {
            get => pool.MaxPoolSize;
            set => pool.MaxPoolSize = value;
        }

        public static TimeSpan ScavengeWindow
        {
            get => pool.ScavengeWindow;
            set => pool.ScavengeWindow = value;
        }

        public static ISocketPool CreateSocketPool() => new SocketPool();

        public override async Task<T> SendMessage<T>(
            string domain,
            ReadOnlyMemory<byte> encoded,
            CancellationToken cancellation = default
        )
        {
            try
            {
                using (var client = await GetClient(domain))
                {
                    var stream = client.GetStream();

                    await WriteMessage(encoded, stream, cancellation);

                    return await ReadResponse<T>(stream, cancellation);
                }
            }
            catch (SocketException sx)
            {
                logger.LogDebug(sx, "TCP Socket exception during Connect {SocketCode}", sx.SocketErrorCode);

                throw new KerberosTransportException("TCP Connect failed", sx);
            }
        }

        private async Task<ITcpSocket> GetClient(string domain)
        {
            var attempts = MaximumAttempts;
            SocketException lastThrown = null;

            do
            {
                var target = LocateKdc(domain);

                logger.LogTrace("TCP connecting to {Target} on port {Port}", target.Target, target.Port);

                ITcpSocket client = null;

                bool connected = false;

                try
                {
                    client = await pool.Request(target, ConnectTimeout);

                    if (client != null)
                    {
                        connected = true;
                    }
                }
                catch (SocketException ex)
                {
                    lastThrown = ex;
                }

                if (!connected)
                {
                    lastThrown = lastThrown ?? new SocketException((int)SocketError.TimedOut);

                    target.Ignore = true;
                    continue;
                }

                logger.LogDebug("TCP connected to {Target} on port {Port}", target.Target, target.Port);

                client.SendTimeout = SendTimeout;
                client.ReceiveTimeout = ReceiveTimeout;

                return client;
            }
            while (--attempts > 0);

            throw lastThrown;
        }

        private async Task<T> ReadResponse<T>(NetworkStream stream, CancellationToken cancellation)
            where T : Asn1.IAsn1ApplicationEncoder<T>, new()
        {
            var messageSizeBytes = await Tcp.ReadFromStream(4, stream, cancellation);

            var messageSize = (int)messageSizeBytes.AsLong();

            var response = await Tcp.ReadFromStream(messageSize, stream, cancellation);

            return Decode<T>(response);
        }

        private static async Task WriteMessage(ReadOnlyMemory<byte> encoded, NetworkStream stream, CancellationToken cancellation)
        {
            encoded = Tcp.FormatKerberosMessageStream(encoded);

            await stream.WriteAsync(encoded.ToArray(), 0, encoded.Length, cancellation);
        }

        protected DnsRecord LocateKdc(string domain)
        {
            var lookup = string.Format(TcpServiceTemplate, domain);

            return QueryDomain(lookup);
        }
    }
}
