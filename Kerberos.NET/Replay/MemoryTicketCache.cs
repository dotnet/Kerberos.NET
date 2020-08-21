﻿// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Kerberos.NET
{
    internal sealed class MemoryTicketCache : TicketCacheBase
    {
        private readonly ConcurrentDictionary<string, CacheEntry> cache
            = new ConcurrentDictionary<string, CacheEntry>();

        public MemoryTicketCache(ILoggerFactory logger)
            : base(logger)
        {
        }

        public bool BlockUpdates { get; set; }

        protected override async Task BackgroundCacheOperation()
        {
            var originalKeys = this.cache.Keys.ToArray();

            foreach (var kv in originalKeys)
            {
                if (!this.cache.TryGetValue(kv, out CacheEntry entry))
                {
                    continue;
                }

                if (entry.IsExpired())
                {
                    this.cache.TryRemove(kv, out _);
                }
                else if (this.RefreshTickets)
                {
                    await (this.Refresh?.Invoke(entry)).ConfigureAwait(true);
                }
            }

            var finalKeys = this.cache.Keys.ToArray();

            var newKeys = finalKeys.Except(originalKeys);
            var purgedKeys = originalKeys.Except(finalKeys);

            if (newKeys.Any() || purgedKeys.Any())
            {
                this.Logger.LogDebug("Cache Operation. New: {NewKeys}; Purged: {PurgedKeys}", string.Join("; ", newKeys), string.Join("; ", purgedKeys));
            }
        }

        public override ValueTask<bool> AddAsync(TicketCacheEntry entry)
        {
            if (this.Add(entry))
            {
                return new ValueTask<bool>(true);
            }

            return new ValueTask<bool>(false);
        }

        public override bool Add(TicketCacheEntry entry)
        {
            var cacheEntry = new CacheEntry(entry.Computed, entry.Value, this.Logger);

            if (entry.Expires > DateTimeOffset.UtcNow)
            {
                cacheEntry.MarkLifetime(entry.Expires, entry.RenewUntil);
            }

            bool added = false;

            if (this.BlockUpdates)
            {
                var got = this.GetInternal(cacheEntry.Key);

                if (got == null)
                {
                    added = this.cache.TryAdd(cacheEntry.Key, cacheEntry);
                }
            }
            else
            {
                this.cache.AddOrUpdate(cacheEntry.Key, cacheEntry, (_, __) => cacheEntry);
                added = true;
            }

            return added;
        }

        public override ValueTask<bool> ContainsAsync(TicketCacheEntry entry)
        {
            var exists = this.cache.ContainsKey(entry.Computed);

            return new ValueTask<bool>(exists);
        }

        public override bool Contains(TicketCacheEntry entry)
        {
            return this.cache.ContainsKey(entry.Computed);
        }

        public override ValueTask<object> GetCacheItemAsync(string key, string container = null)
        {
            return new ValueTask<object>(this.GetCacheItem(key, container));
        }

        public override object GetCacheItem(string key, string container = null)
        {
            var entryKey = TicketCacheEntry.GenerateKey(key: key, container: container);

            return this.GetInternal(entryKey);
        }

        public override T GetCacheItem<T>(string key, string container = null)
        {
            var result = this.GetCacheItem(key, container);

            if (result is T value)
            {
                return value;
            }

            return default;
        }

        private object GetInternal(string entryKey)
        {
            if (this.cache.TryGetValue(entryKey, out CacheEntry entry))
            {
                if (entry.IsExpired())
                {
                    this.Evict(entryKey);
                }
                else
                {
                    return entry.Value;
                }
            }

            return null;
        }

        private void Evict(string entryKey)
        {
            var removed = this.cache.TryRemove(entryKey, out _);

            this.Logger.LogDebug($"Removal triggered for {entryKey}. Succeeded: {removed}");
        }

        public override async ValueTask<T> GetCacheItemAsync<T>(string key, string container = null)
        {
            var result = await this.GetCacheItemAsync(key, container).ConfigureAwait(true);

            return result != null ? (T)result : default;
        }

        [DebuggerDisplay("{Key}; E: {Expiration}; R: {RenewUntil};")]
        internal class CacheEntry
        {
            private readonly ILogger logger;

            public CacheEntry(
                string key,
                object value,
                ILogger logger
            )
            {
                this.Key = key;
                this.Value = value;
                this.logger = logger;
            }

            public string Key { get; }

            public object Value { get; }

            public DateTimeOffset? Expiration { get; private set; }

            public DateTimeOffset? RenewUntil { get; private set; }

            public TimeSpan TimeToLive => (this.Expiration ?? DateTimeOffset.MaxValue) - DateTimeOffset.UtcNow;

            public void MarkLifetime(DateTimeOffset expiration, DateTimeOffset? renewUntil)
            {
                this.logger.LogTrace("Caching ticket until {Expiration} for {Key} with renewal option until {RenewUntil}", expiration, this.Key, renewUntil);

                this.Expiration = expiration;
                this.RenewUntil = renewUntil;
            }

            public bool IsExpired()
            {
                return this.TimeToLive <= TimeSpan.Zero;
            }
        }
    }
}
