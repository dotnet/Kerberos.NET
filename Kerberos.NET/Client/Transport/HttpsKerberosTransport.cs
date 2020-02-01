using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

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

        private static readonly Lazy<HttpClient> lazyHttp = new Lazy<HttpClient>();

        public string CustomVirtualPath { get; set; }

        public bool TryResolvingServiceLocator { get; set; }

        public IDictionary<string, Uri> DomainPaths { get; set; } = new Dictionary<string, Uri>();

        public DcLocatorHint Hint { get; set; }

        protected virtual HttpClient Client => lazyHttp.Value;

        public override async Task<T> SendMessage<T>(string domain, ReadOnlyMemory<byte> req, CancellationToken cancellation = default)
        {
            var kdc = LocateKdc(domain);

            var message = KdcProxyMessage.WrapMessage(req, domain, Hint);

            var response = await Client.PostAsync(kdc, new BinaryContent(message.Encode()));

            if (response.Content == null)
            {
                response.EnsureSuccessStatusCode();
            }

            var responseBody = await response.Content.ReadAsByteArrayAsync();

            if (!KdcProxyMessage.TryDecode(responseBody, out KdcProxyMessage kdcResponse))
            {
                response.EnsureSuccessStatusCode();

                string body = "";

                if (responseBody.Length > 0)
                {
                    body = Encoding.UTF8.GetString(responseBody);
                }

                throw new KerberosProtocolException($"Cannot process HTTP Response: {body}");
            }

            return Decode<T>(kdcResponse.UnwrapMessage());
        }

        protected Uri LocateKdc(string domain)
        {
            domain = domain.ToLowerInvariant();

            if (DomainPaths.TryGetValue(domain, out Uri uri))
            {
                return uri;
            }

            if (TryResolvingServiceLocator)
            {
                uri = ResolveByServiceLocator(domain);
            }

            if (uri == null)
            {
                uri = new Uri($"https://{domain}/");
            }

            var path = CustomVirtualPath ?? WellKnownKdcProxyPath;

            uri = new Uri(uri, path);

            DomainPaths[domain] = uri;

            return uri;
        }

        private Uri ResolveByServiceLocator(string domain)
        {
            var lookup = string.Format(HttpsServiceTemplate, domain);

            var dnsRecord = QueryDomain(lookup);

            if (dnsRecord == null)
            {
                return null;
            }

            return new Uri($"https://{dnsRecord.Target}:{dnsRecord.Port}/");
        }
    }
}
