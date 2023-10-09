using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Threading.Tasks;
using Kerberos.NET.Configuration;
using Kerberos.NET.Dns;
using Microsoft.Extensions.Logging;
using static System.FormattableString;

namespace Kerberos.NET.Transport
{
    public class ClientDomainService
    {
        public ClientDomainService(ILoggerFactory logger)
        {
            this.logger = logger.CreateLoggerSafe<ClientDomainService>();
        }

        internal const int DefaultKerberosPort = 88;

        internal const int DefaultKpasswdPort = 464;

        private static readonly Task CacheCleanup;

        private static readonly ConcurrentDictionary<string, DnsRecord> DomainCache
            = new ConcurrentDictionary<string, DnsRecord>(StringComparer.InvariantCultureIgnoreCase);

        private static readonly ConcurrentDictionary<string, DateTimeOffset> DomainServiceNegativeCache
            = new ConcurrentDictionary<string, DateTimeOffset>(StringComparer.InvariantCultureIgnoreCase);

        private readonly Dictionary<string, HashSet<string>> pinnedKdcs
            = new Dictionary<string, HashSet<string>>(StringComparer.InvariantCultureIgnoreCase);

        private readonly ConcurrentDictionary<string, DnsRecord> negativeCache
            = new ConcurrentDictionary<string, DnsRecord>(StringComparer.InvariantCultureIgnoreCase);

        private readonly ILogger logger;

        static ClientDomainService()
        {
            CacheCleanup = Task.Run(MonitorDnsCache).ContinueWith(t => t.Dispose(), TaskScheduler.Default);
        }

        public static TimeSpan CacheCleanupInterval { get; set; } = TimeSpan.FromMinutes(5);

        public Krb5Config Configuration { get; set; }

        public void ResetConnections()
        {
            DomainCache.Clear();
            DomainServiceNegativeCache.Clear();
            this.pinnedKdcs.Clear();
            this.negativeCache.Clear();
        }

        public virtual async Task<IEnumerable<DnsRecord>> LocateKdc(string domain, string servicePrefix)
        {
            var results = await this.Query(domain, servicePrefix, DefaultKerberosPort);

            return ParseQuerySrvReply(results);
        }

        public virtual async Task<IEnumerable<DnsRecord>> LocateKpasswd(string domain, string servicePrefix)
        {
            var results = await this.Query(domain, servicePrefix, DefaultKpasswdPort);

            return ParseQuerySrvReply(results);
        }

        public virtual IEnumerable<DnsRecord> ParseQuerySrvReply(IEnumerable<DnsRecord> reply)
        {
            var results = reply.Where(r => r.Type == DnsRecordType.SRV);

            results = results.Where(s => !this.negativeCache.TryGetValue(s.Target, out DnsRecord record) || record.Expired);

            foreach (var result in results.Where(r => r.Expired).ToList())
            {
                this.negativeCache.TryRemove(result.Target, out _);
            }

            var weighted = results.GroupBy(r => r.Weight)
                                  .OrderBy(r => r.Key)
                                  .ThenByDescending(r => r.Sum(a => a.Canonical.Count()))
                                  .FirstOrDefault();

            if (weighted != null)
            {
                return weighted;
            }

            return Array.Empty<DnsRecord>();
        }

        public void NegativeCache(DnsRecord record)
        {
            if (record != null)
            {
                this.negativeCache[record.Target] = record;
            }
        }

        public void PinKdc(string realm, string kdc)
        {
            DomainCache.TryRemove(realm, out _);

            if (!this.pinnedKdcs.TryGetValue(realm, out HashSet<string> kdcs))
            {
                kdcs = new HashSet<string>();
                this.pinnedKdcs[realm] = kdcs;
            }

            kdcs.Add(kdc);
        }

        public void ClearPinnedKdc(string realm)
        {
            DomainCache.TryRemove(realm, out _);

            if (this.pinnedKdcs.TryGetValue(realm, out HashSet<string> kdcs))
            {
                kdcs.Clear();
            }
        }

        protected virtual async Task<IEnumerable<DnsRecord>> Query(string domain, string servicePrefix, int defaultPort)
        {
            var records = new List<DnsRecord>();

            if (this.pinnedKdcs.TryGetValue(domain, out HashSet<string> kdcs))
            {
                records.AddRange(kdcs.Select(k => ParseKdcEntryAsSrvRecord(k, domain, servicePrefix, defaultPort)).Where(k => k != null));
            }

            if (this.Configuration.Realms.TryGetValue(domain, out Krb5RealmConfig config))
            {
                records.AddRange(config.Kdc.Select(k => ParseKdcEntryAsSrvRecord(k, domain, servicePrefix, defaultPort)).Where(k => k != null));
            }

            if (this.Configuration.Defaults.DnsLookupKdc)
            {
                try
                {
                    await this.QueryDns(domain, servicePrefix, records);
                }
                catch (DnsNotSupportedException ex)
                {
                    this.logger.LogDebug(ex, "DNS isn't supported on this platform");
                }
            }

            return records;
        }

        private async Task QueryDns(string domain, string servicePrefix, List<DnsRecord> records)
        {
            var lookup = Invariant($"{servicePrefix}.{domain}");

            bool skipLookup = false;

            if (DomainServiceNegativeCache.TryGetValue(lookup, out DateTimeOffset expires))
            {
                if (DateTimeOffset.UtcNow > expires)
                {
                    DomainServiceNegativeCache.TryRemove(lookup, out _);
                }
                else
                {
                    skipLookup = true;
                }
            }

            if (!skipLookup)
            {
                this.logger.LogDebug("Querying DNS {Lookup}", lookup);

                var dnsResults = await DnsQuery.QuerySrv(lookup);

                if (!dnsResults.Any())
                {
                    DomainServiceNegativeCache[lookup] = DateTimeOffset.UtcNow.AddMinutes(5);

                    this.logger.LogDebug("DNS failed {Lookup} so negative caching", lookup);
                }

                records.AddRange(dnsResults);
            }
        }

        private static DnsRecord ParseKdcEntryAsSrvRecord(string kdc, string realm, string servicePrefix, int defaultPort)
        {
            if (IsUri(kdc))
            {
                return new DnsRecord
                {
                    Target = kdc,
                    Type = DnsRecordType.SRV,
                    Name = realm
                };
            }

            var split = kdc.Split(':');

            var record = new DnsRecord
            {
                Target = split[0],
                Type = DnsRecordType.SRV,
                Name = $"{servicePrefix}.{realm}"
            };

            if (split.Length > 1)
            {
                record.Port = int.Parse(split[1], CultureInfo.InvariantCulture);
            }
            else
            {
                record.Port = defaultPort;
            }

            return record;
        }

        private static bool IsUri(string kdc)
        {
            return Uri.TryCreate(kdc, UriKind.Absolute, out Uri result) &&
                ("https".Equals(result.Scheme, StringComparison.OrdinalIgnoreCase) ||
                 "http".Equals(result.Scheme, StringComparison.OrdinalIgnoreCase));
        }

        private static async Task MonitorDnsCache()
        {
            // allows any callers to modify CacheCleanupInterval
            // without having to wait the full 5 minute default.

            await Task.Delay(TimeSpan.FromSeconds(5));

            // yes this is somewhat redundant

            while (!CacheCleanup.IsCompleted)
            {
                foreach (var entry in DomainCache.ToList())
                {
                    if (entry.Value.Expired)
                    {
                        DomainCache.TryRemove(entry.Key, out _);
                    }
                }

                foreach (var entry in DomainServiceNegativeCache.ToList())
                {
                    if (DateTimeOffset.UtcNow > entry.Value)
                    {
                        DomainServiceNegativeCache.TryRemove(entry.Key, out _);
                    }
                }

                await Task.Delay(CacheCleanupInterval);
            }
        }
    }
}
