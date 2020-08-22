// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Globalization;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Kerberos.NET.Dns;

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
            this.Enabled = false;
        }

        public override async Task<T> SendMessage<T>(
            string domain,
            ReadOnlyMemory<byte> encoded,
            CancellationToken cancellation = default
        )
        {
            var target = this.LocateKdc(domain);

            using (var client = new UdpClient(target.Target, target.Port))
            {
                cancellation.ThrowIfCancellationRequested();

                var result = await client.SendAsync(encoded.ToArray(), encoded.Length).ConfigureAwait(true);

                cancellation.ThrowIfCancellationRequested();

                var response = await client.ReceiveAsync().ConfigureAwait(true);

                return Decode<T>(response.Buffer);
            }
        }

        protected DnsRecord LocateKdc(string domain)
        {
            var lookup = string.Format(CultureInfo.InvariantCulture, UdpServiceTemplate, domain);

            return this.QueryDomain(lookup);
        }
    }
}