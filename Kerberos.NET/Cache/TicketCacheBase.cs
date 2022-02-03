// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Kerberos.NET.Client;
using Kerberos.NET.Configuration;
using Microsoft.Extensions.Logging;
using static Kerberos.NET.MemoryTicketCache;

namespace Kerberos.NET
{
    public abstract class TicketCacheBase : ITicketCache2, IDisposable
    {
        private readonly Task backgroundRunner;
        private bool disposedValue;

        public TicketCacheBase(Krb5Config config, ILoggerFactory logger)
        {
            this.Configuration = config;
            this.Logger = logger.CreateLoggerSafe<TicketCacheBase>();

            this.Cancellation = new CancellationTokenSource();

            this.backgroundRunner = Task.Run(this.RunBackground, this.Cancellation.Token);
        }

        public bool RefreshTickets { get; set; }

        public TimeSpan RefreshInterval { get; set; } = TimeSpan.FromSeconds(30);

        public virtual string DefaultDomain { get; set; }

        internal Func<CacheEntry, Task> Refresh { get; set; }

        protected Krb5Config Configuration { get; }

        protected CancellationTokenSource Cancellation { get; }

        protected ILogger Logger { get; }

        public static void TryParseCacheType(string cachePath, out string cacheType, out string path)
        {
            if (TryParseAsFile(cachePath, out cacheType, out path))
            {
                return;
            }

            if (TryParseAsLsa(cachePath, out cacheType, out path))
            {
                return;
            }

            var indexOf = cachePath.IndexOf(':');

            if (indexOf > 1)
            {
                cacheType = cachePath.Substring(0, indexOf).ToUpperInvariant();
                path = cachePath.Substring(indexOf + 1);
            }
        }

        private static readonly IEnumerable<string> LsaCacheTypes = new[] { "mslsa:", "mslsa", "lsa:", "lsa" };

        private static bool TryParseAsLsa(string cachePath, out string cacheType, out string path)
        {
            cacheType = null;
            path = null;

            if (LsaCacheTypes.Any(c => c.Equals(cachePath, StringComparison.OrdinalIgnoreCase)))
            {
                cacheType = "mslsa";
                return true;
            }

            return false;
        }

        private static bool TryParseAsFile(string cachePath, out string cacheType, out string path)
        {
            cacheType = null;
            path = null;

            var indexOf = cachePath.IndexOf(':');

            if (indexOf <= 0)
            {
                return false;
            }
            else if (indexOf == 1 ||
                     cachePath[0] == Path.DirectorySeparatorChar ||
                     cachePath[0] == Path.AltDirectorySeparatorChar)
            {
                // assume drive letter

                cacheType = "FILE";
                path = cachePath;

                return true;
            }
            else if (indexOf > 1 && cachePath.Substring(0, indexOf).Equals("FILE", StringComparison.OrdinalIgnoreCase))
            {
                // not a drive letter

                cacheType = cachePath.Substring(0, indexOf).ToUpperInvariant();
                path = cachePath.Substring(indexOf + 1);

                return true;
            }

            return false;
        }

        private async Task RunBackground()
        {
            while (!this.Cancellation.IsCancellationRequested)
            {
                try
                {
                    await this.BackgroundCacheOperation().ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    this.Logger.LogWarning(ex, "Background cache operation failed");
                }

                await Task.Delay(this.RefreshInterval, this.Cancellation.Token).ConfigureAwait(false);
            }
        }

        protected virtual async Task BackgroundCacheOperation()
        {
            if (!this.RefreshTickets)
            {
                return;
            }

            var cacheObjects = await this.GetAllAsync();

            foreach (var cacheObject in cacheObjects)
            {
                CacheEntry cacheEntry = null;

                if (cacheObject is KerberosClientCacheEntry kerbEntry)
                {
                    cacheEntry = new CacheEntry("", kerbEntry, this.Logger);
                }
                else if (cacheObject is CacheEntry entry)
                {
                    cacheEntry = entry;
                }

                if (cacheEntry != null && !cacheEntry.IsExpired(this.Configuration.Defaults.ClockSkew))
                {
                    await (this.Refresh?.Invoke(cacheEntry)).ConfigureAwait(false);
                }
            }

            var finalKeys = await this.GetAllAsync();

            var newKeys = finalKeys.Except(cacheObjects);
            var purgedKeys = cacheObjects.Except(finalKeys);

            if (newKeys.Any() || purgedKeys.Any())
            {
                this.Logger.LogDebug(
                    "Cache Operation. New: {NewKeys}; Purged: {PurgedKeys}",
                    string.Join("; ", newKeys),
                    string.Join("; ", purgedKeys)
                );
            }
        }

        public abstract ValueTask<bool> AddAsync(TicketCacheEntry entry);

        public abstract bool Add(TicketCacheEntry entry);

        public abstract ValueTask<bool> ContainsAsync(TicketCacheEntry entry);

        public abstract bool Contains(TicketCacheEntry entry);

        public abstract ValueTask<object> GetCacheItemAsync(string key, string container = null);

        public abstract object GetCacheItem(string key, string container = null);

        public abstract ValueTask<T> GetCacheItemAsync<T>(string key, string container = null);

        public abstract T GetCacheItem<T>(string key, string container = null);

        public virtual void PurgeTickets()
        {
        }

        public virtual Task PurgeTicketsAsync()
        {
            this.PurgeTickets();

            return Task.CompletedTask;
        }

        public virtual IEnumerable<object> GetAll()
        {
            return Array.Empty<object>();
        }

        public virtual Task<IEnumerable<object>> GetAllAsync()
        {
            return Task.FromResult(this.GetAll());
        }

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
