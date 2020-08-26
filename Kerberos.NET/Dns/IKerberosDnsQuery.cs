// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System.Collections.Generic;
using System.Threading.Tasks;

namespace Kerberos.NET.Dns
{
    /// <summary>
    /// Provides a mechanism to query for DNS records as used by Kerberos.
    /// </summary>
    public interface IKerberosDnsQuery
    {
        /// <summary>
        /// Make a DNS lookup for the provided query and record type.
        /// </summary>
        /// <param name="query">The query to send to the DNS server.</param>
        /// <param name="type">The requested record type of the query.</param>
        /// <returns>Returns zero or more results from the query.</returns>
        Task<IEnumerable<DnsRecord>> Query(string query, DnsRecordType type);
    }
}
