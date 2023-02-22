// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Kerberos.NET.Dns;

public class POSIXDnsQuery : IKerberosDnsQuery
{
    public bool Debug { get; set; }

    public bool IsSupported => OSPlatform.IsLinux;

    public Task<IReadOnlyCollection<DnsRecord>> Query(string query, DnsRecordType type)
    {
        if (!IsSupported)
        {
            throw new InvalidOperationException("The POSIX DNS query implementation is not supported outside of POSIX-compliant systems");
        }

        var result = DnsQueryWin32.QuerySrvRecord(query, type);

        return Task.FromResult(result);
    }
}
