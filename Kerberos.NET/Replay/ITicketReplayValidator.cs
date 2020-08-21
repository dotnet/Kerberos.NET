// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Threading.Tasks;

namespace Kerberos.NET
{
    public interface ITicketReplayValidator
    {
        Task<bool> Add(TicketCacheEntry entry);

        Task<bool> Contains(TicketCacheEntry entry);
    }

    public class TicketCacheEntry
    {
        public string Computed => GenerateKey(this.Container, this.Key);

        internal static string GenerateKey(string container = null, string key = null)
        {
            return $"kerberos-{container?.ToLowerInvariant()}-{key?.ToLowerInvariant()}";
        }

        public string Key { get; set; }

        public string Container { get; set; }

        public DateTimeOffset Expires { get; set; }

        public DateTimeOffset? RenewUntil { get; set; }

        public object Value { get; set; }
    }
}