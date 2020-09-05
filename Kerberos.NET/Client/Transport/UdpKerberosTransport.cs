// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Kerberos.NET.Asn1;
using Kerberos.NET.Dns;
using Kerberos.NET.Entities;
using Microsoft.Extensions.Logging;

namespace Kerberos.NET.Transport
{
    public class UdpKerberosTransport : KerberosTransportBase
    {
        private const string UdpServiceTemplate = "_kerberos._udp";

        private readonly ILogger logger;

        public UdpKerberosTransport(ILoggerFactory logger)
            : base(logger)
        {
            this.logger = logger.CreateLoggerSafe<UdpKerberosTransport>();
            this.Enabled = true;
        }

        public override async Task<T> SendMessage<T>(
            string domain,
            ReadOnlyMemory<byte> encoded,
            CancellationToken cancellation = default
        )
        {
            if (this.Configuration.Defaults.UdpPreferenceLimit < encoded.Length)
            {
                throw new KerberosTransportException(new KrbError { ErrorCode = KerberosErrorCode.KRB_ERR_RESPONSE_TOO_BIG });
            }

            var target = await this.LocatePreferredKdc(domain, UdpServiceTemplate);

            this.logger.LogTrace("UDP connecting to {Target} on port {Port}", target.Target, target.Port);

            try
            {
                return await SendMessage<T>(encoded, target, cancellation);
            }
            catch (SocketException)
            {
                this.ClientRealmService.NegativeCache(target);
                throw;
            }
        }

        private static async Task<T> SendMessage<T>(ReadOnlyMemory<byte> encoded, DnsRecord target, CancellationToken cancellation)
            where T : IAsn1ApplicationEncoder<T>, new()
        {
            using (var client = new UdpClient(target.Target, target.Port))
            {
                cancellation.ThrowIfCancellationRequested();

                var result = await client.SendAsync(encoded.ToArray(), encoded.Length).ConfigureAwait(true);

                cancellation.ThrowIfCancellationRequested();

                var response = await client.ReceiveAsync().ConfigureAwait(true);

                return Decode<T>(response.Buffer);
            }
        }
    }
}
