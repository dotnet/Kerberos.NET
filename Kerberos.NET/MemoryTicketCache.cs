using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;

namespace Kerberos.NET
{
    internal sealed class MemoryTicketCache
    {
        private readonly CancellationTokenSource cancel = new CancellationTokenSource();

        private class CacheEntry
        {
            private readonly ConcurrentDictionary<string, CacheEntry> cache;

            public CacheEntry(
                ConcurrentDictionary<string, CacheEntry> cache,
                string key,
                object value
            )
            {
                this.cache = cache;
                this.Key = key;
                this.Value = value;
            }

            public string Key { get; }

            public object Value { get; }

            public void BeginTriggerDelay(TimeSpan lifetime, CancellationToken cancel)
            {
                Task.Delay(lifetime, cancel).ContinueWith(RemoveSelf);
            }

            private void RemoveSelf(Task task)
            {
                cache.TryRemove(Key, out _);
            }
        }

        private readonly ConcurrentDictionary<string, CacheEntry> cache
            = new ConcurrentDictionary<string, CacheEntry>();

        public Task<bool> Add(TicketCacheEntry entry)
        {
            bool added = false;

            var cacheEntry = new CacheEntry(cache, entry.Computed, null);

            if (cache.TryAdd(cacheEntry.Key, cacheEntry))
            {
                var lifetime = entry.Expires - DateTimeOffset.UtcNow;

                if (lifetime > TimeSpan.Zero)
                {
                    cacheEntry.BeginTriggerDelay(entry.Expires - DateTimeOffset.UtcNow, cancel.Token);

                    added = true;
                }
            }

            return Task.FromResult(added);
        }

        public Task<bool> Contains(TicketCacheEntry entry)
        {
            var exists = cache.ContainsKey(entry.Computed);

            return Task.FromResult(exists);
        }
    }
}
