// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Buffers.Binary;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Kerberos.NET.Client;
using Microsoft.Extensions.Logging;

namespace Kerberos.NET.Transport
{
    public class TcpKerberosTransport : KerberosTransportBase
    {
        private const string TcpServiceTemplate = "_kerberos._tcp";
        private const string TcpServiceTemplatePasswd = "_kpasswd._tcp";

        private static readonly ISocketPool Pool = CreateSocketPool();

        private readonly ILogger<TcpKerberosTransport> logger;

        public TcpKerberosTransport(ILoggerFactory logger)
            : base(logger)
        {
            this.logger = logger.CreateLoggerSafe<TcpKerberosTransport>();

            this.Enabled = true;
        }

        public static int MaxPoolSize
        {
            get => Pool.MaxPoolSize;
            set => Pool.MaxPoolSize = value;
        }

        public static TimeSpan ScavengeWindow
        {
            get => Pool.ScavengeWindow;
            set => Pool.ScavengeWindow = value;
        }

        public static ISocketPool CreateSocketPool() => new SocketPool();

        public override async Task<ReadOnlyMemory<byte>> SendMessage(
            string domain,
            ReadOnlyMemory<byte> encoded,
            CancellationToken cancellation = default
        )
        {
            return await SendMessageTCP(domain, encoded, cancellation, () => { return this.LocatePreferredKdc(domain, TcpServiceTemplate); });
        }

        public override async Task<ReadOnlyMemory<byte>> SendMessageChangePassword(
            string domain,
            ReadOnlyMemory<byte> encoded,
            CancellationToken cancellation = default
        )
        {
            return await SendMessageTCP(domain, encoded, cancellation, () => { return this.LocatePreferredKpasswd(domain, TcpServiceTemplatePasswd); });
        }

        private async Task<ReadOnlyMemory<byte>> SendMessageTCP(
            string domain,
            ReadOnlyMemory<byte> encoded,
            CancellationToken cancellation,
            Func<Task<Dns.DnsRecord>> locatePreferredServer
        )
        {
            try
            {
                using (var client = await this.GetClient(locatePreferredServer).ConfigureAwait(false))
                {
                    var stream = client.GetStream();

                    await WriteMessage(encoded, stream, cancellation).ConfigureAwait(false);

                    return await ReadResponse(stream, cancellation, this.ReceiveTimeout).ConfigureAwait(false);
                }
            }
            catch (SocketException sx)
            {
                this.logger.LogDebug(sx, "TCP Socket exception during Connect {SocketCode}", sx.SocketErrorCode);

                throw new KerberosTransportException("TCP Connect failed", sx);
            }
        }

        private async Task<ITcpSocket> GetClient(Func<Task<Dns.DnsRecord>> locatePreferredServer)
        {
            var attempts = this.MaximumAttempts;
            SocketException lastThrown = null;

            do
            {
                var target = await locatePreferredServer();

                this.logger.LogTrace("TCP connecting to {Target} on port {Port}", target.Target, target.Port);

                ITcpSocket client = null;

                bool connected = false;

                try
                {
                    client = await Pool.Request(target, this.ConnectTimeout).ConfigureAwait(false);

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

                    this.ClientRealmService.NegativeCache(target);

                    continue;
                }

                this.logger.LogDebug("TCP connected to {Target} on port {Port}", target.Target, target.Port);

                client.SendTimeout = this.SendTimeout;
                client.ReceiveTimeout = this.ReceiveTimeout;

                return client;
            }
            while (--attempts > 0);

            throw lastThrown;
        }

        private static async Task<ReadOnlyMemory<byte>> ReadResponse(NetworkStream stream, CancellationToken cancellation, TimeSpan readTimeout)
        {
            using (var messageSizeBytesRented = CryptoPool.Rent<byte>(4))
            {
                var messageSizeBytes = messageSizeBytesRented.Memory.Slice(0, 4);

                await Tcp.ReadFromStream(messageSizeBytes, stream, cancellation, readTimeout).ConfigureAwait(false);

                var messageSize = BinaryPrimitives.ReadInt32BigEndian(messageSizeBytes.Span);

                var response = await Tcp.ReadFromStream(messageSize, stream, cancellation, readTimeout).ConfigureAwait(false);

                return response;
            }
        }

        private static async Task WriteMessage(ReadOnlyMemory<byte> encoded, NetworkStream stream, CancellationToken cancellation)
        {
            var length = encoded.Length + 4;

            using (var messageRented = CryptoPool.Rent<byte>(length))
            {
                var message = messageRented.Memory.Slice(0, length);

                Tcp.FormatKerberosMessageStream(encoded, message);

                await stream.WriteAsync(message, cancellation).ConfigureAwait(false);
            }
        }
    }
}
