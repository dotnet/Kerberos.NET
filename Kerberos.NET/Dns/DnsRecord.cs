// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Kerberos.NET.Dns
{
    [DebuggerDisplay("{Type} {Target} {Weight}")]
    public class DnsRecord
    {
        private readonly DateTimeOffset stamp;

        public DnsRecord()
        {
            this.stamp = DateTimeOffset.UtcNow;
        }

        public string Name { get; set; }

        public string Target { get; set; }

        public IEnumerable<DnsRecord> Canonical { get; set; } = new List<DnsRecord>();

        public DnsRecordType Type { get; set; }

        public int TimeToLive { get; set; }

        public int Priority { get; set; }

        public int Weight { get; set; }

        public int Port { get; set; }

        public bool Ignore { get; set; }

        public bool Purge => this.Ignore || this.Expired;

        public bool Expired => this.stamp.AddSeconds(this.TimeToLive) <= DateTimeOffset.UtcNow;

        public string Address => $"{this.Target}:{this.Port}";
    }
}