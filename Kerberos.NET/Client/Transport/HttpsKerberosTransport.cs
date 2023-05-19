// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Kerberos.NET.Asn1;
using Kerberos.NET.Entities;
using Microsoft.Extensions.Logging;

namespace Kerberos.NET.Transport
{
    public class HttpsKerberosTransport : KerberosTransportBase
    {
        private static readonly Random Random = new();

        private readonly ILogger logger;

        public HttpsKerberosTransport(ILoggerFactory logger = null)
            : base(logger)
        {
            this.logger = logger.CreateLoggerSafe<HttpsKerberosTransport>();
            this.Enabled = true;
        }

        private const string HttpsServicePrefix = "_kerberos._https";
        private const string WellKnownKdcProxyPath = "/KdcProxy";

        private const string RequestIdHeader = "x-ms-request-id";
        private const string CorrelationIdHeader = "client-request-id";

        private static readonly Lazy<HttpClient> LazyHttp = new();

        public string CustomVirtualPath { get; set; }

        public IDictionary<string, Uri> DomainPaths { get; } = new Dictionary<string, Uri>();

        public DcLocatorHint Hint { get; set; }

        protected virtual HttpClient Client => LazyHttp.Value;

        public string RequestId { get; private set; }

        public override async Task<T> SendMessage<T>(string domain, ReadOnlyMemory<byte> req, CancellationToken cancellation = default)
        {
            var kdc = await this.LocateKdc(domain);

            if (kdc == null)
            {
                throw new KerberosTransportException($"Cannot locate a KDC Proxy endpoint for {domain}");
            }

            this.logger.LogInformation("KDC target found {KDC}", kdc);

            try
            {
                return await this.SendMessage<T>(domain, req, kdc);
            }
            catch (KerberosTransportException kex)
            {
                var error = kex.Error ?? new KrbError();

                error.EText = this.GetErrorText(kex.Message);

                throw new KerberosTransportException(kex.Error);
            }
            catch (KerberosProtocolException kex)
            {
                var error = kex.Error ?? new KrbError();

                error.EText = this.GetErrorText(kex.Message);

                if (error.ErrorCode == KerberosErrorCode.KDC_ERR_NONE)
                {
                    error.ErrorCode = KerberosErrorCode.KDC_ERR_SVC_UNAVAILABLE;
                }

                throw new KerberosProtocolException(error);
            }
            catch (HttpRequestException hex)
            {
                var errorMessage = this.GetErrorText(hex.Message);

                throw new HttpRequestException(errorMessage, hex);
            }
            catch (Exception ex)
            {
                var errorMessage = this.GetErrorText(ex.Message);

                throw new KerberosProtocolException(errorMessage, ex);
            }
        }

        private string GetErrorText(string errorMessage)
        {
            string message = errorMessage;

            if (!string.IsNullOrWhiteSpace(this.RequestId))
            {
                message = $"{errorMessage} [RequestId:{this.RequestId}]".Trim();
            }

            return message;
        }

        private async Task<T> SendMessage<T>(string domain, ReadOnlyMemory<byte> req, Uri kdc)
            where T : IAsn1ApplicationEncoder<T>, new()
        {
            var message = KdcProxyMessage.WrapMessage(req, domain, this.Hint);

            using (var content = new BinaryContent(message.Encode()))
            {
                content.Headers.Add(CorrelationIdHeader, this.ScopeId.ToString());

                var response = await this.Client.PostAsync(kdc, content).ConfigureAwait(false);

                this.TryParseRequestId(response);

                if (response.Content == null)
                {
                    response.EnsureSuccessStatusCode();
                }

                var responseBody = await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);

                if (!responseBody.Any())
                {
                    response.EnsureSuccessStatusCode();
                }

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

        private void TryParseRequestId(HttpResponseMessage response)
        {
            if (response.Headers.TryGetValues(RequestIdHeader, out IEnumerable<string> values))
            {
                this.RequestId = values.FirstOrDefault();
            }
        }

        private async Task<Uri> LocateKdc(string domain)
        {
            if (string.IsNullOrWhiteSpace(domain))
            {
                throw new ArgumentNullException(nameof(domain));
            }

            if (this.DomainPaths.TryGetValue(domain.ToLowerInvariant(), out Uri uri))
            {
                return uri;
            }

            uri = await this.LocatePreferredKdc(domain);

            return uri;
        }

        private async Task<Uri> LocatePreferredKdc(string domain)
        {
            var results = await this.LocateKdc(domain, HttpsServicePrefix);

            results = results.Where(r => r.Address.StartsWith("https://") || r.Address.StartsWith("http://"));

            var rand = Random.Next(0, results?.Count() ?? 0);

            var record = results?.ElementAtOrDefault(rand);

            if (record == null)
            {
                return null;
            }

            var uri = new Uri(record.Target);

            if (record.Name.StartsWith(HttpsServicePrefix))
            {
                var path = this.CustomVirtualPath ?? WellKnownKdcProxyPath;

                uri = new Uri(uri, path);
            }

            this.DomainPaths[domain] = uri;

            return uri;
        }
    }
}
