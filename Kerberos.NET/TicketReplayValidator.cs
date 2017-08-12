using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;

namespace Kerberos.NET
{
    internal class TicketReplayValidator : ITicketReplayValidator
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

        public Task<byte[]> GetAsync(string key)
        {
            return Task.FromResult(Get(key));
        }

        public void Refresh(string key)
        {
            /* refreshing */
        }

        public Task RefreshAsync(string key)
        {
            return Task.FromResult(0);
        }

        public void Remove(string key)
        {
            base.Remove(key);
        }

        public Task RemoveAsync(string key)
        {
            base.Remove(key);

            return Task.FromResult(0);
        }

        public void Set(string key, byte[] value, DistributedCacheEntryOptions options)
        {
            var created = CreateEntry(key);

            created.SetValue(value);
        }

        public Task SetAsync(string key, byte[] value, DistributedCacheEntryOptions options)
        {
            Set(key, value, options);

            return Task.FromResult(0);
        }
    }
}