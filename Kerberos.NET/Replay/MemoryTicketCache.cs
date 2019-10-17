using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;

namespace Kerberos.NET
{
    internal sealed class MemoryTicketCache : ITicketCache, IDisposable
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

            private Task triggerCleanup;

            public void BeginTriggerDelay(TimeSpan lifetime, CancellationToken cancel)
            {
                LogWrite($"Triggering delay {lifetime} for {Key}");

                TimeSpan delay = lifetime;

                if (delay > TimeSpan.FromDays(7))
                {
                    delay = TimeSpan.FromDays(7);
                }

                triggerCleanup = Task.Delay(delay, cancel).ContinueWith(RemoveSelf, cancel);
            }

            private void LogWrite(string log, Exception ex = null)
            {
                if (ex == null)
                {
                    logger?.WriteLine(KerberosLogSource.Cache, log);
                }
                else
                {
                    logger?.WriteLine(KerberosLogSource.Cache, log, ex);
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

                GC.KeepAlive(triggerCleanup);
            }
        }

        private readonly ConcurrentDictionary<string, CacheEntry> cache
            = new ConcurrentDictionary<string, CacheEntry>();

        public Task<bool> Add(TicketCacheEntry entry)
        {
            bool added = false;

            var cacheEntry = new CacheEntry(cache, entry.Computed, entry.Value, logger);

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

        public Task<object> Get(string key, string container = null)
        {
            if (cache.TryGetValue(TicketCacheEntry.GenerateKey(key: key, container: container), out CacheEntry entry))
            {
                return Task.FromResult(entry.Value);
            }

            return Task.FromResult<object>(null);
        }

        public async Task<T> Get<T>(string key, string container = null)
        {
            var result = await Get(key, container);

            return result != null ? (T)result : default;
        }

        public void Dispose()
        {
            cancel.Cancel();
            cancel.Dispose();
        }
    }
}
