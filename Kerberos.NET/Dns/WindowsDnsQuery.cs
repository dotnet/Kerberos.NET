// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Kerberos.NET.Dns
{
    public class WindowsDnsQuery : IKerberosDnsQuery
    {
        public bool Debug { get; set; }

        public bool IsSupported => OSPlatform.IsWindows;

        public Task<IReadOnlyCollection<DnsRecord>> Query(string query, DnsRecordType type)
        {
            if (!this.IsSupported)
            {
                throw new InvalidOperationException("The win32 DNS query implementation is not supported outside of Windows");
            }

            var result = DnsQueryWin32.QuerySrvRecord(query, type);

            return Task.FromResult(result);
        }
    }
}
