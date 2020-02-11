using Microsoft.Extensions.Logging;
using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Kerberos.NET
{
    internal sealed class MemoryTicketCache : ITicketCache, IDisposable
    {
        private readonly ILogger logger;
        private readonly Task backgroundRunner;
        private readonly CancellationTokenSource cts;

        public MemoryTicketCache(ILoggerFactory logger)
        {
            this.logger = logger.CreateLoggerSafe<MemoryTicketCache>();

            cts = new CancellationTokenSource();

            backgroundRunner = Task.Run(RunBackground, cts.Token);
            backgroundRunner.ContinueWith(t => t, cts.Token);
        }

        internal Func<CacheEntry, Task> Refresh { get; set; }

        public bool RefreshTickets { get; set; }

        public TimeSpan RefreshInterval { get; set; } = TimeSpan.FromSeconds(30);

        private async Task RunBackground()
        {
            while (true)
            {
                if (cts.Token.IsCancellationRequested)
                {
                    break;
                }

                try
                {
                    await BackgroundCacheOperation();
                }
                catch (Exception ex)
                {
                    logger.LogWarning(ex, "Background cache operation failed");
                }

                await Task.Delay(RefreshInterval, cts.Token);
            }
        }

        private async Task BackgroundCacheOperation()
        {
            var originalKeys = cache.Keys.ToArray();

            foreach (var kv in originalKeys)
            {
                if (!cache.TryGetValue(kv, out CacheEntry entry))
                {
                    continue;
                }

                if (entry.IsExpired())
                {
                    cache.TryRemove(kv, out _);
                }
                else if (RefreshTickets)
                {
                    await Refresh?.Invoke(entry);
                }
            }

            var finalKeys = cache.Keys.ToArray();

            var newKeys = finalKeys.Except(originalKeys);
            var purgedKeys = originalKeys.Except(finalKeys);

            if (newKeys.Any() || purgedKeys.Any())
            {
                logger.LogDebug("Cache Operation. New: {NewKeys}; Purged: {PurgedKeys}", string.Join("; ", newKeys), string.Join("; ", purgedKeys));
            }
        }

        private readonly ConcurrentDictionary<string, CacheEntry> cache
            = new ConcurrentDictionary<string, CacheEntry>();

        public bool BlockUpdates { get; set; }

        public async Task<bool> Add(TicketCacheEntry entry)
        {
            var cacheEntry = new CacheEntry(entry.Computed, entry.Value, logger);

            if (entry.Expires > DateTimeOffset.UtcNow)
            {
                cacheEntry.MarkLifetime(entry.Expires, entry.RenewUntil);
            }

            bool added = false;

            if (BlockUpdates)
            {
                var got = await GetInternal(cacheEntry.Key);

                if (got == null)
                {
                    added = cache.TryAdd(cacheEntry.Key, cacheEntry);
                }
            }
            else
            {
                cache.AddOrUpdate(cacheEntry.Key, cacheEntry, (_, __) => cacheEntry);
                added = true;
            }

            return added;
        }

        public Task<bool> Contains(TicketCacheEntry entry)
        {
            var exists = cache.ContainsKey(entry.Computed);

            return Task.FromResult(exists);
        }

        public Task<object> Get(string key, string container = null)
        {
            var entryKey = TicketCacheEntry.GenerateKey(key: key, container: container);

            return GetInternal(entryKey);
        }

        private Task<object> GetInternal(string entryKey)
        {
            if (cache.TryGetValue(entryKey, out CacheEntry entry))
            {
                if (entry.IsExpired())
                {
                    Evict(entryKey);
                }
                else
                {
                    return Task.FromResult(entry.Value);
                }
            }

            return Task.FromResult<object>(null);
        }

        private void Evict(string entryKey)
        {
            var removed = cache.TryRemove(entryKey, out _);

            logger.LogDebug($"Removal triggered for {entryKey}. Succeeded: {removed}");
        }

        public async Task<T> Get<T>(string key, string container = null)
        {
            var result = await Get(key, container);

            return result != null ? (T)result : default;
        }

        public void Dispose()
        {
            cts.Cancel();
            cts.Dispose();
            backgroundRunner.Dispose();
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

            public TimeSpan TimeToLive => (Expiration ?? DateTimeOffset.MaxValue) - DateTimeOffset.UtcNow;

            public void MarkLifetime(DateTimeOffset expiration, DateTimeOffset? renewUntil)
            {
                logger.LogTrace("Caching ticket until {Expiration} for {Key} with renewal option until {RenewUntil}", expiration, Key, renewUntil);

                Expiration = expiration;
                RenewUntil = renewUntil;
            }

            public bool IsExpired()
            {
                return TimeToLive <= TimeSpan.Zero;
            }
        }
    }
}
