using System;
using System.Collections.Concurrent;
using System.Runtime.Caching;

namespace Syfuhs.Security.Kerberos
{
    internal class TicketReplayValidator : ITicketReplayValidator
    {
        private static readonly ConcurrentDictionary<string, ObjectCache> CacheRegions = new ConcurrentDictionary<string, ObjectCache>();

        public bool Add(TicketCacheEntry entry)
        {
            var tokenCache = GetOrCreate(entry.Container);

            var cacheItem = new CacheItem(entry.Key, entry.Key, entry.Container);

            return tokenCache.Add(
                cacheItem,
                new CacheItemPolicy
                {
                    AbsoluteExpiration = entry.Expires
                }
            );
        }

        private static ObjectCache GetOrCreate(string region)
        {
            ObjectCache cache;

            if (!CacheRegions.TryGetValue(region, out cache))
            {
                cache = new MemoryCache(region);

                CacheRegions[region] = cache;
            }

            return cache;
        }

        public bool Contains(TicketCacheEntry entry)
        {
            ObjectCache cache;

            if (!CacheRegions.TryGetValue(entry.Container, out cache))
            {
                return false;
            }

            return cache.Contains(entry.Key);
        }
    }
}