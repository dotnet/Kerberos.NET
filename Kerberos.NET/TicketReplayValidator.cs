#if NET46
using System.Collections.Concurrent;
using System.Runtime.Caching;
using System.Threading.Tasks;
#else
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;
using System.Threading;
#endif

namespace Kerberos.NET
{
#if NET46
    internal class TicketReplayValidator : ITicketReplayValidator
    {
        private static readonly ConcurrentDictionary<string, ObjectCache> CacheRegions = new ConcurrentDictionary<string, ObjectCache>();

        public Task<bool> Add(TicketCacheEntry entry)
        {
            var tokenCache = GetOrCreate(entry.Container);

            var cacheItem = new CacheItem(entry.Key, entry.Key, entry.Container);

            var result = tokenCache.Add(
                cacheItem,
                new CacheItemPolicy
                {
                    AbsoluteExpiration = entry.Expires
                }
            );

            return Task.FromResult(result);
        }

        private static ObjectCache GetOrCreate(string region)
        {
            if (!CacheRegions.TryGetValue(region, out ObjectCache cache))
            {
                cache = new MemoryCache(region);

                CacheRegions[region] = cache;
            }

            return cache;
        }

        public Task<bool> Contains(TicketCacheEntry entry)
        {
            if (!CacheRegions.TryGetValue(entry.Container, out ObjectCache cache))
            {
                return Task.FromResult(false);
            }

            return Task.FromResult(cache.Contains(entry.Key));
        }
    }
#else
    public class TicketReplayValidator : ITicketReplayValidator
    {
        private readonly IDistributedCache cache;

        public TicketReplayValidator(IDistributedCache cache = null)
        {
            this.cache = cache ?? new DistributedMemoryCache();
        }

        public async Task<bool> Add(TicketCacheEntry entry)
        {
            if (await Contains(entry))
            {
                return false;
            }

            await cache.SetStringAsync(entry.Computed, entry.Key, new DistributedCacheEntryOptions { AbsoluteExpiration = entry.Expires });

            return true;
        }

        public async Task<bool> Contains(TicketCacheEntry entry)
        {
            var existing = await cache.GetStringAsync(entry.Computed);

            return !string.IsNullOrWhiteSpace(existing);
        }
    }

    internal class DistributedMemoryCache : MemoryCache, IDistributedCache
    {
        private class DistributedMemoryOptions : IOptions<MemoryCacheOptions>
        {
            public MemoryCacheOptions Value => new MemoryCacheOptions();
        }

        public DistributedMemoryCache() : base(new DistributedMemoryOptions())
        {
        }

        public byte[] Get(string key)
        {
            TryGetValue(key, out object result);

            return result as byte[];
        }

        public Task<byte[]> GetAsync(string key, CancellationToken token = default(CancellationToken))
        {
            return Task.FromResult(Get(key));
        }

        public void Refresh(string key)
        {
            /* refreshing */
        }

        public Task RefreshAsync(string key, CancellationToken token = default(CancellationToken))
        {
            return Task.FromResult(0);
        }

        public void Remove(string key)
        {
            base.Remove(key);
        }

        public Task RemoveAsync(string key, CancellationToken token = default(CancellationToken))
        {
            base.Remove(key);

            return Task.FromResult(0);
        }

        public void Set(string key, byte[] value, DistributedCacheEntryOptions options)
        {
            var created = CreateEntry(key);

            created.SetValue(value);
        }

        public Task SetAsync(string key, byte[] value, DistributedCacheEntryOptions options, CancellationToken token = default(CancellationToken))
        {
            Set(key, value, options);

            return Task.FromResult(0);
        }
    }
#endif
}