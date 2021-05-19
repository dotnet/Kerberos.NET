using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using DnsClient;
using Kerberos.NET.Dns;

namespace Kerberos.NET.CommandLine.Dns
{
    internal class PlatformIndependentDnsClient : IKerberosDnsQuery
    {
        private static readonly WindowsDnsQuery WindowsDns = new WindowsDnsQuery();

        public async Task<IReadOnlyCollection<DnsRecord>> Query(string query, DnsRecordType type)
        {
            if (WindowsDns.IsSupported)
            {
                return await WindowsDns.Query(query, type);
            }

            var client = new LookupClient();

            var response = await client.QueryAsync(query, (QueryType)type);

            var srvRecords = response.Answers.SrvRecords().Select(a => new DnsRecord
            {
                Name = a.DomainName,
                Port = a.Port,
                Priority = a.Priority,
                Target = a.Target,
                TimeToLive = a.TimeToLive,
                Type = DnsRecordType.SRV,
                Weight = a.Weight
            }).ToList();

            var merged = srvRecords.GroupBy(r => r.Name);

            foreach (var srv in srvRecords)
            {
                var c1 = merged.Where(m => m.Key.Equals(srv.Target, StringComparison.InvariantCultureIgnoreCase));

                var canon = c1.SelectMany(r => r);

                srv.Canonical = canon.ToList();
            }

            return srvRecords;
        }
    }
}
