using Kerberos.NET.Asn1;
using Kerberos.NET.Dns;
using Kerberos.NET.Entities;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Kerberos.NET.Transport
{
    public abstract class KerberosTransportBase : IKerberosTransport, IDisposable
    {
        private const int DefaultKerberosPort = 88;

        private readonly string kdc;

        private static readonly Random random = new Random();

        private readonly ConcurrentDictionary<string, DnsRecord> negativeCache
            = new ConcurrentDictionary<string, DnsRecord>();

        protected KerberosTransportBase(string kdc = null)
        {
            this.kdc = kdc;
        }

        private static readonly ConcurrentDictionary<string, DnsRecord> DomainCache
            = new ConcurrentDictionary<string, DnsRecord>();

        public virtual bool TransportFailed { get; set; }

        public virtual KerberosTransportException LastError { get; set; }

        public bool Enabled { get; set; }

        public TimeSpan ConnectTimeout { get; set; } = TimeSpan.FromSeconds(2);

        public TimeSpan SendTimeout { get; set; } = TimeSpan.FromSeconds(10);

        public TimeSpan ReceiveTimeout { get; set; } = TimeSpan.FromSeconds(10);

        public int MaximumAttempts { get; set; } = 30;

        protected static T Decode<T>(ReadOnlyMemory<byte> response)
            where T : IAsn1ApplicationEncoder<T>, new()
        {
            if (KrbError.CanDecode(response))
            {
                var error = KrbError.DecodeApplication(response);

                if (error.ErrorCode == KerberosErrorCode.KRB_ERR_RESPONSE_TOO_BIG)
                {
                    throw new KerberosTransportException(error);
                }

                throw new KerberosProtocolException(error);
            }

            return new T().DecodeAsApplication(response);
        }

        public virtual Task<TResponse> SendMessage<TRequest, TResponse>(
            string domain,
            IAsn1ApplicationEncoder<TRequest> req,
            CancellationToken cancellation = default
        ) where TResponse : IAsn1ApplicationEncoder<TResponse>, new()
        {
            return SendMessage<TResponse>(domain, req.EncodeApplication());
        }

        public abstract Task<T> SendMessage<T>(
            string domain,
            ReadOnlyMemory<byte> req,
            CancellationToken cancellation = default
        ) where T : IAsn1ApplicationEncoder<T>, new();

        protected virtual DnsRecord QueryDomain(string lookup)
        {
            return DomainCache.AddOrUpdate(
                lookup, // find SRV by domain name in cache
                dn => QueryDns(dn, null), // if it doesn't exist in cache just query and add
                (dn, existing) => existing.Purge ? QueryDns(dn, existing) : existing // if it already exists check if its ignored and replace
            );
        }

        private DnsRecord QueryDns(string lookup, DnsRecord ignored)
        {
            if (!string.IsNullOrWhiteSpace(kdc))
            {
                var split = kdc.Split(':');

                var record = new DnsRecord
                {
                    Target = split[0]
                };

                if (split.Length > 1)
                {
                    record.Port = int.Parse(split[1]);
                }
                else
                {
                    record.Port = DefaultKerberosPort;
                }

                return record;
            }

            var results = Query(lookup).Where(r => r.Type == DnsRecordType.SRV);

            if (ignored != null && ignored.Ignore)
            {
                // can get here through expiration, and we don't actually want to negative cache
                // something that has just expired because it could still genuinely be good

                negativeCache[ignored.Target] = ignored;
            }

            results = results.Where(s => !negativeCache.TryGetValue(s.Target, out DnsRecord record) || record.Expired);

            var weighted = results.GroupBy(r => r.Weight).OrderBy(r => r.Key).OrderByDescending(r => r.Sum(a => a.Canonical.Count())).FirstOrDefault();

            var rand = random.Next(0, weighted?.Count() ?? 0);

            var srv = weighted?.ElementAtOrDefault(rand);

            if (srv == null)
            {
                throw new KerberosTransportException($"Cannot locate SRV record for {lookup}");
            }

            if (srv.Port <= 0)
            {
                srv.Port = DefaultKerberosPort;
            }

            return srv;
        }

        protected virtual IEnumerable<DnsRecord> Query(string lookup)
        {
            return DnsQuery.QuerySrv(lookup);
        }

        public virtual void Dispose() { }
    }
}
