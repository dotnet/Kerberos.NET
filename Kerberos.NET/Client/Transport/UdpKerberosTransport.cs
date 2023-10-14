// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Kerberos.NET.Dns;
using Kerberos.NET.Entities;
using Microsoft.Extensions.Logging;
using static Kerberos.NET.BinaryExtensions;

namespace Kerberos.NET.Transport
{
    public class UdpKerberosTransport : KerberosTransportBase
    {
        private const string UdpServiceTemplate = "_kerberos._udp";
        private const string UdpServiceTemplatePasswd = "_kpasswd._udp";

        private readonly ILogger logger;

        public UdpKerberosTransport(ILoggerFactory logger)
            : base(logger)
        {
            this.logger = logger.CreateLoggerSafe<UdpKerberosTransport>();
            this.Enabled = true;
        }

        public override async Task<ReadOnlyMemory<byte>> SendMessage(
            string domain,
            ReadOnlyMemory<byte> encoded,
            CancellationToken cancellation = default
        )
        {
            return await SendMessageUDP(domain, encoded, cancellation, () => { return this.LocatePreferredKdc(domain, UdpServiceTemplate); });
        }

        public override async Task<ReadOnlyMemory<byte>> SendMessageChangePassword(
            string domain,
            ReadOnlyMemory<byte> encoded,
            CancellationToken cancellation = default
        )
        {
            return await SendMessageUDP(domain, encoded, cancellation, () => { return this.LocatePreferredKpasswd(domain, UdpServiceTemplatePasswd); });
        }

        private async Task<ReadOnlyMemory<byte>> SendMessageUDP(
            string domain,
            ReadOnlyMemory<byte> encoded,
            CancellationToken cancellation,
            Func<Task<Dns.DnsRecord>> locatePreferredServer
        )
        {
            if (this.Configuration.Defaults.UdpPreferenceLimit < encoded.Length)
            {
                throw new KerberosTransportException(new KrbError { ErrorCode = KerberosErrorCode.KRB_ERR_RESPONSE_TOO_BIG });
            }

            var target = await locatePreferredServer();

            this.logger.LogTrace("UDP connecting to {Target} on port {Port}", target.Target, target.Port);

            try
            {
                return await SendMessage(encoded, target, cancellation);
            }
            catch (SocketException)
            {
                this.ClientRealmService.NegativeCache(target);
                throw;
            }
        }

        private static async Task<byte[]> SendMessage(ReadOnlyMemory<byte> encoded, DnsRecord target, CancellationToken cancellation)
        {
            using (var client = new UdpClient(target.Target, target.Port))
            {
                cancellation.ThrowIfCancellationRequested();

                var result = await client.SendAsync(TryGetArrayFast(encoded), encoded.Length).ConfigureAwait(false);

                cancellation.ThrowIfCancellationRequested();

                var response = await client.ReceiveAsync().ConfigureAwait(false);

                return response.Buffer;
            }
        }
    }
}
