// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Kerberos.NET.Dns
{
    /// <summary>
    /// Provides a mechanism to query for SRV DNS records.
    /// </summary>
    public static class DnsQuery
    {
        private static readonly object SyncImpl = new object();
        private static IKerberosDnsQuery QueryImplementation;

        static DnsQuery()
        {
            if (OSPlatform.IsWindows)
            {
                QueryImplementation = new WindowsDnsQuery();
                return;
            }
            //for now assume it's POSIX
            QueryImplementation = new POSIXDnsQuery();
        }

        public static bool Debug
        {
            get => QueryImplementation.Debug;
            set => QueryImplementation.Debug = value;
        }

        /// <summary>
        /// Register a custom DNS implementation for outbound queries.
        /// </summary>
        /// <param name="dnsQuery">The query implementation to register.</param>
        public static void RegisterImplementation(IKerberosDnsQuery dnsQuery)
        {
            if (dnsQuery == null)
            {
                throw new ArgumentNullException(nameof(dnsQuery));
            }

            lock (SyncImpl)
            {
                QueryImplementation = dnsQuery;
            }
        }

        /// <summary>
        /// Contact a DNS server and request an SRV record for the provided query value.
        /// SRV queries hold the form _service._proto.name.
        /// </summary>
        /// <param name="query">The query value to send to the server.</param>
        /// <returns>Returns zero or more SRV records for requested query value.</returns>
        public static async Task<IEnumerable<DnsRecord>> QuerySrv(string query)
        {
            IKerberosDnsQuery implementation = LoadImplementation();

            if (implementation == null)
            {
                throw new DnsNotSupportedException("DNS Query implementation cannot be null");
            }

            if (Debug)
            {
                System.Diagnostics.Debug.WriteLine($"Trying to query for {query}");
            }

            return await implementation.Query(query, DnsRecordType.SRV);
        }

        private static IKerberosDnsQuery LoadImplementation()
        {
            IKerberosDnsQuery implementation;

            lock (SyncImpl)
            {
                implementation = QueryImplementation;
            }

            return implementation;
        }
    }
}
