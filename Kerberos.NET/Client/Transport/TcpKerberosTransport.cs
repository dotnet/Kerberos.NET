﻿using System;
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

        private readonly ILogger<TcpKerberosTransport> logger;

        public TcpKerberosTransport(ILoggerFactory logger, string kdc = null)
            : base(kdc)
        {
            this.logger = logger.CreateLoggerSafe<TcpKerberosTransport>();

            Enabled = true;
        }

        public override async Task<T> SendMessage<T>(
            string domain,
            ReadOnlyMemory<byte> encoded,
            CancellationToken cancellation = default
        )
        {
            var attempts = MaximumAttempts;
            SocketException lastThrown = null;

            do
            {
                var target = LocateKdc(domain);

                logger.LogInformation("TCP connecting to {Target} on port {Port}", target.Target, target.Port);

                using (var client = new TcpClient(AddressFamily.InterNetwork))
                {
                    client.LingerState = new LingerOption(false, 0);

                    try
                    {
                        client.SendTimeout = (int)ConnectTimeout.TotalMilliseconds;
                        client.ReceiveTimeout = (int)ConnectTimeout.TotalMilliseconds;

                        await client.ConnectAsync(target.Target, target.Port);
                    }
                    catch (SocketException sx)
                    {
                        lastThrown = sx;
                        target.Ignore = true;

                        continue;
                    }

                    var stream = client.GetStream();

                    await WriteMessage(encoded, stream, cancellation);

                    return await ReadResponse<T>(stream, cancellation);
                }
            }
            while (--attempts > 0);

            logger.LogDebug(lastThrown, "TCP Socket exception during Connect {SocketCode}", lastThrown.SocketErrorCode);

            throw new KerberosTransportException("TCP Connect failed", lastThrown);
        }

        private async Task<T> ReadResponse<T>(NetworkStream stream, CancellationToken cancellation)
            where T : Asn1.IAsn1ApplicationEncoder<T>, new()
        {
            var messageSizeBytes = await ReadFromStream(4, stream, cancellation);

            var messageSize = (int)messageSizeBytes.AsLong();

            var response = await ReadFromStream(messageSize, stream, cancellation);

            return Decode<T>(response);
        }

        private static async Task<byte[]> ReadFromStream(int messageSize, NetworkStream stream, CancellationToken cancellation)
        {
            var response = new byte[messageSize];

            int read = 0;

            while (read < response.Length)
            {
                read += await stream.ReadAsync(
                    response,
                    read,
                    response.Length - read,
                    cancellation
                );
            }

            return response;
        }

        private static async Task WriteMessage(ReadOnlyMemory<byte> encoded, NetworkStream stream, CancellationToken cancellation)
        {
            var messageSizeBytes = new byte[sizeof(int)];

            BinaryPrimitives.WriteInt32BigEndian(messageSizeBytes, encoded.Length);

            await stream.WriteAsync(messageSizeBytes, 0, messageSizeBytes.Length, cancellation);

            await stream.WriteAsync(encoded.ToArray(), 0, encoded.Length, cancellation);

            await stream.FlushAsync();
        }

        protected DnsRecord LocateKdc(string domain)
        {
            var lookup = string.Format(TcpServiceTemplate, domain);

            return QueryDomain(lookup);
        }
    }
}
