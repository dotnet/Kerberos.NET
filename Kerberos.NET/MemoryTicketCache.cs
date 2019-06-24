using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;

namespace Kerberos.NET
{
    internal sealed class MemoryTicketCache
    {
        private readonly ILogger logger;

        public MemoryTicketCache(ILogger logger)
        {
            this.logger = logger;
        }

        private readonly CancellationTokenSource cancel = new CancellationTokenSource();

        private class CacheEntry
        {
            private readonly ConcurrentDictionary<string, CacheEntry> cache;
            private readonly ILogger logger;

            public CacheEntry(
                ConcurrentDictionary<string, CacheEntry> cache,
                string key,
                object value,
                ILogger logger
            )
            {
                this.cache = cache;
                this.Key = key;
                this.Value = value;
                this.logger = logger;
            }

            public string Key { get; }

            public object Value { get; }

            public void BeginTriggerDelay(TimeSpan lifetime, CancellationToken cancel)
            {
                LogWrite($"Triggering delay {lifetime} for {Key}");

                Task.Delay(lifetime, cancel).ContinueWith(RemoveSelf);
            }

            private void LogWrite(string log, Exception ex = null)
            {
                if (ex == null)
                {
                    logger.WriteLine(KerberosLogSource.ReplayCache, log);
                }
                else
                {
                    logger.WriteLine(KerberosLogSource.ReplayCache, log, ex);
                }
            }

            private void RemoveSelf(Task task)
            {
                if (task.IsFaulted)
                {
                    LogWrite($"Removal failed for {Key}", task.Exception);
                }

                var removed = cache.TryRemove(Key, out CacheEntry removedEntry);

                LogWrite($"Removal triggered for {removedEntry.Key}. Succeeded: {removed}");
            }
        }

        private readonly ConcurrentDictionary<string, CacheEntry> cache
            = new ConcurrentDictionary<string, CacheEntry>();

        public Task<bool> Add(TicketCacheEntry entry)
        {
            bool added = false;

            var cacheEntry = new CacheEntry(cache, entry.Computed, null, logger);

            if (cache.TryAdd(cacheEntry.Key, cacheEntry))
            {
                var lifetime = entry.Expires - DateTimeOffset.UtcNow;

                if (lifetime > TimeSpan.Zero)
                {
                    cacheEntry.BeginTriggerDelay(lifetime, cancel.Token);

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
