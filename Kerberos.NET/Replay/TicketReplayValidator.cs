// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Kerberos.NET
{
    public class TicketReplayValidator : ITicketReplayValidator, IDisposable
    {
        private readonly MemoryTicketCache cache;
        private bool disposedValue;

        public TicketReplayValidator(ILoggerFactory logger)
        {
            this.cache = new MemoryTicketCache(logger) { BlockUpdates = true };
        }

        public async Task<bool> Add(TicketCacheEntry entry)
        {
            if (entry == null)
            {
                throw new ArgumentNullException(nameof(entry));
            }

            return await this.cache.AddAsync(entry).ConfigureAwait(true);
        }

        public async Task<bool> Contains(TicketCacheEntry entry)
        {
            var got = await this.cache.GetCacheItemAsync(entry?.Key).ConfigureAwait(true);

            return got != null;
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!this.disposedValue)
            {
                if (disposing)
                {
                    this.cache?.Dispose();
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