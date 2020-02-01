using Microsoft.Extensions.Logging;
using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;

namespace Kerberos.NET
{
    internal sealed class MemoryTicketCache : ITicketCache, IDisposable
    {
        private readonly ILogger logger;
        private readonly Task backgroundCleanup;
        private readonly CancellationTokenSource cts;

        public MemoryTicketCache(ILoggerFactory logger)
        {
            this.logger = logger.CreateLoggerSafe<MemoryTicketCache>();

            cts = new CancellationTokenSource();

            backgroundCleanup = Task.Run(Cleanup, cts.Token);
            backgroundCleanup.ContinueWith(t => { }, cts.Token);
        }

        private async Task Cleanup()
        {
            while (true)
            {
                if (cts.Token.IsCancellationRequested)
                {
                    break;
                }

                foreach (var kv in this.cache.Keys)
                {
                    if (cache.TryGetValue(kv, out CacheEntry entry) && entry.IsExpired())
                    {
                        cache.TryRemove(kv, out _);
                    }
                }

                await Task.Delay(TimeSpan.FromMinutes(5), cts.Token);
            }
        }

        private readonly ConcurrentDictionary<string, CacheEntry> cache
            = new ConcurrentDictionary<string, CacheEntry>();

        public bool BlockUpdates { get; set; }

        public async Task<bool> Add(TicketCacheEntry entry)
        {
            var cacheEntry = new CacheEntry(entry.Computed, entry.Value, logger);

            var lifetime = entry.Expires - DateTimeOffset.UtcNow;

            if (lifetime > TimeSpan.Zero)
            {
                cacheEntry.MarkLifetime(lifetime);
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
        }

        private class CacheEntry
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

            public void MarkLifetime(TimeSpan lifetime)
            {
                logger.LogTrace($"Triggering delay {lifetime} for {Key}");

                TimeSpan delay = lifetime;

                if (delay > TimeSpan.FromDays(7))
                {
                    delay = TimeSpan.FromDays(7);
                }

                Expiration = DateTimeOffset.UtcNow + delay;
            }

            public bool IsExpired()
            {
                return Expiration.HasValue && Expiration.Value <= DateTimeOffset.UtcNow;
            }
        }
    }
}
