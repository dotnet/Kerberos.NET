using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using System;
using System.Collections.Generic;
using System.Net.Http;
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

            var messageBytes = new Memory<byte>(new byte[req.Length + 4]);

            Endian.ConvertToBigEndian(req.Length, messageBytes.Slice(0, 4));
            req.CopyTo(messageBytes.Slice(4, req.Length));

            var message = new KdcProxyMessage
            {
                TargetDomain = domain,
                KerbMessage = messageBytes,
                DcLocatorHint = Hint
            };

            var response = await Client.PostAsync(kdc, new BinaryContent(message.Encode()));

            response.EnsureSuccessStatusCode();

            var responseBody = await response.Content.ReadAsByteArrayAsync();

            var kdcResponse = KdcProxyMessage.Decode(responseBody);

            return Decode<T>(kdcResponse.KerbMessage.Slice(4));
        }

        protected Uri LocateKdc(string domain)
        {
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
