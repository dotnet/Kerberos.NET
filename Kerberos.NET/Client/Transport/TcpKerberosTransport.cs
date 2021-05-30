// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Kerberos.NET.Client;
using Microsoft.Extensions.Logging;

namespace Kerberos.NET.Transport
{
    public class TcpKerberosTransport : KerberosTransportBase
    {
        private const string TcpServiceTemplate = "_kerberos._tcp";

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

        public override async Task<T> SendMessage<T>(
            string domain,
            ReadOnlyMemory<byte> encoded,
            CancellationToken cancellation = default
        )
        {
            try
            {
                using (var client = await this.GetClient(domain).ConfigureAwait(false))
                {
                    var stream = client.GetStream();

                    await WriteMessage(encoded, stream, cancellation).ConfigureAwait(false);

                    return await ReadResponse<T>(stream, cancellation).ConfigureAwait(false);
                }
            }
            catch (SocketException sx)
            {
                this.logger.LogDebug(sx, "TCP Socket exception during Connect {SocketCode}", sx.SocketErrorCode);

                throw new KerberosTransportException("TCP Connect failed", sx);
            }
        }

        private async Task<ITcpSocket> GetClient(string domain)
        {
            var attempts = this.MaximumAttempts;
            SocketException lastThrown = null;

            do
            {
                var target = await this.LocatePreferredKdc(domain, TcpServiceTemplate);

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

        private static async Task<T> ReadResponse<T>(NetworkStream stream, CancellationToken cancellation)
            where T : Asn1.IAsn1ApplicationEncoder<T>, new()
        {
            var messageSizeBytes = await Tcp.ReadFromStream(4, stream, cancellation).ConfigureAwait(false);

            var messageSize = (int)messageSizeBytes.AsLong();

            var response = await Tcp.ReadFromStream(messageSize, stream, cancellation).ConfigureAwait(false);

            return Decode<T>(response);
        }

        private static async Task WriteMessage(ReadOnlyMemory<byte> encoded, NetworkStream stream, CancellationToken cancellation)
        {
            encoded = Tcp.FormatKerberosMessageStream(encoded);

            await stream.WriteAsync(encoded.ToArray(), 0, encoded.Length, cancellation).ConfigureAwait(false);
        }
    }
}
