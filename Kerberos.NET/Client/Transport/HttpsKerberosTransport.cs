// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Kerberos.NET.Entities;

namespace Kerberos.NET.Transport
{
    public class HttpsKerberosTransport : KerberosTransportBase
    {
        public HttpsKerberosTransport()
        {
            this.Enabled = true;
        }

        private const string HttpsServiceTemplate = "_kerberos._https.{0}";
        private const string WellKnownKdcProxyPath = "/KdcProxy";

        private static readonly Lazy<HttpClient> LazyHttp = new Lazy<HttpClient>();

        public string CustomVirtualPath { get; set; }

        public bool TryResolvingServiceLocator { get; set; }

        public IDictionary<string, Uri> DomainPaths { get; } = new Dictionary<string, Uri>();

        public DcLocatorHint Hint { get; set; }

        protected virtual HttpClient Client => LazyHttp.Value;

        public override async Task<T> SendMessage<T>(string domain, ReadOnlyMemory<byte> req, CancellationToken cancellation = default)
        {
            var kdc = await this.LocateKdc(domain);

            var message = KdcProxyMessage.WrapMessage(req, domain, this.Hint);

            using (var content = new BinaryContent(message.Encode()))
            {
                var response = await this.Client.PostAsync(kdc, content).ConfigureAwait(true);

                if (response.Content == null)
                {
                    response.EnsureSuccessStatusCode();
                }

                var responseBody = await response.Content.ReadAsByteArrayAsync().ConfigureAwait(true);

                if (!KdcProxyMessage.TryDecode(responseBody, out KdcProxyMessage kdcResponse))
                {
                    response.EnsureSuccessStatusCode();

                    string body = string.Empty;

                    if (responseBody.Length > 0)
                    {
                        body = Encoding.UTF8.GetString(responseBody);
                    }

                    throw new KerberosProtocolException($"Cannot process HTTP Response: {body}");
                }

                return Decode<T>(kdcResponse.UnwrapMessage());
            }
        }

        protected async Task<Uri> LocateKdc(string domain)
        {
            if (string.IsNullOrWhiteSpace(domain))
            {
                throw new ArgumentNullException(nameof(domain));
            }

            domain = domain.ToLowerInvariant();

            if (this.DomainPaths.TryGetValue(domain, out Uri uri))
            {
                return uri;
            }

            if (this.TryResolvingServiceLocator)
            {
                uri = await this.ResolveByServiceLocator(domain);
            }

            if (uri == null)
            {
                uri = new Uri($"https://{domain}/");
            }

            var path = this.CustomVirtualPath ?? WellKnownKdcProxyPath;

            uri = new Uri(uri, path);

            this.DomainPaths[domain] = uri;

            return uri;
        }

        private async Task<Uri> ResolveByServiceLocator(string domain)
        {
            var lookup = string.Format(CultureInfo.InvariantCulture, HttpsServiceTemplate, domain);

            var dnsRecord = await this.QueryDomain(lookup);

            if (dnsRecord == null)
            {
                return null;
            }

            return new Uri($"https://{dnsRecord.Target}:{dnsRecord.Port}/");
        }
    }
}
