using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using static Kerberos.NET.MemoryTicketCache;

namespace Kerberos.NET
{
    public abstract class TicketCacheBase : ITicketCache, IDisposable
    {
        private readonly Task backgroundRunner;

        public TicketCacheBase(ILoggerFactory logger)
        {
            this.Logger = logger.CreateLoggerSafe<TicketCacheBase>();

            this.Cancellation = new CancellationTokenSource();

            this.backgroundRunner = Task.Run(this.RunBackground, this.Cancellation.Token);
        }

        public bool RefreshTickets { get; set; }

        public TimeSpan RefreshInterval { get; set; } = TimeSpan.FromSeconds(30);

        internal Func<CacheEntry, Task> Refresh { get; set; }

        protected CancellationTokenSource Cancellation { get; }

        protected ILogger Logger { get; }

        private async Task RunBackground()
        {
            while (!this.Cancellation.IsCancellationRequested)
                try
                {
                    await this.BackgroundCacheOperation().ConfigureAwait(true);
                }
                catch (Exception ex)
                {
                    this.Logger.LogWarning(ex, "Background cache operation failed");
                }

                await Task.Delay(this.RefreshInterval, this.Cancellation.Token).ConfigureAwait(true);
            }
        }

        protected virtual Task BackgroundCacheOperation()
        {
            return Task.CompletedTask;
        }

        public void Dispose()
        {
            this.Cancellation.Cancel();
            this.Cancellation.Dispose();

            this.backgroundRunner.ContinueWith(t => t.Dispose(), TaskScheduler.Default);
        }

        public abstract ValueTask<bool> AddAsync(TicketCacheEntry entry);

        public abstract bool Add(TicketCacheEntry entry);

        public abstract ValueTask<bool> ContainsAsync(TicketCacheEntry entry);

        public abstract bool Contains(TicketCacheEntry entry);

        public abstract ValueTask<object> GetCacheItemAsync(string key, string container = null);

        public abstract object GetCacheItem(string key, string container = null);

        public abstract ValueTask<T> GetCacheItemAsync<T>(string key, string container = null);

        public abstract T GetCacheItem<T>(string key, string container = null);
    }
}
