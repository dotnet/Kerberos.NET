// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

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
        private bool disposedValue;

        public TicketCacheBase(ILoggerFactory logger)
        {
            this.Logger = logger.CreateLoggerSafe<TicketCacheBase>();

            this.Cancellation = new CancellationTokenSource();

            this.backgroundRunner = Task.Run(this.RunBackground, this.Cancellation.Token);
        }

        public bool RefreshTickets { get; set; }

        public TimeSpan RefreshInterval { get; set; } = TimeSpan.FromSeconds(30);

        public virtual string DefaultDomain { get; set; }

        internal Func<CacheEntry, Task> Refresh { get; set; }

        protected CancellationTokenSource Cancellation { get; }

        protected ILogger Logger { get; }

        public static void TryParseCacheType(string cachePath, out string cacheType, out string path)
        {
            cacheType = null;
            path = cachePath;

            var indexOf = cachePath.IndexOf(':');

            if (indexOf > 1)
            {
                // not a drive letter

                cacheType = cachePath.Substring(0, indexOf).ToUpperInvariant();
                path = cachePath.Substring(indexOf + 1);
            }
        }

        private async Task RunBackground()
        {
            while (!this.Cancellation.IsCancellationRequested)
            {
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

        public abstract ValueTask<bool> AddAsync(TicketCacheEntry entry);

        public abstract bool Add(TicketCacheEntry entry);

        public abstract ValueTask<bool> ContainsAsync(TicketCacheEntry entry);

        public abstract bool Contains(TicketCacheEntry entry);

        public abstract ValueTask<object> GetCacheItemAsync(string key, string container = null);

        public abstract object GetCacheItem(string key, string container = null);

        public abstract ValueTask<T> GetCacheItemAsync<T>(string key, string container = null);

        public abstract T GetCacheItem<T>(string key, string container = null);

        protected virtual void Dispose(bool disposing)
        {
            if (!this.disposedValue)
            {
                if (disposing)
                {
                    this.Cancellation.Cancel();
                    this.Cancellation.Dispose();

                    this.backgroundRunner.ContinueWith(t => t.Dispose(), TaskScheduler.Default);
                }

                this.disposedValue = true;
            }
        }

        public void Dispose()
        {
            this.Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }
}
