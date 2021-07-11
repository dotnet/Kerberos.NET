// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Threading.Tasks;
using Kerberos.NET.Configuration;
using Microsoft.Extensions.Logging;

namespace Kerberos.NET
{
    public class TicketReplayValidator : ITicketReplayValidator, IDisposable
    {
        private readonly MemoryTicketCache cache;
        private bool disposedValue;

        public TicketReplayValidator(ILoggerFactory logger)
            : this(Krb5Config.Default(), logger)
        { }

        public TicketReplayValidator(Krb5Config config, ILoggerFactory logger)
        {
            this.cache = new MemoryTicketCache(config, logger) { BlockUpdates = true };
        }

        public async Task<bool> Add(TicketCacheEntry entry)
        {
            if (entry == null)
            {
                throw new ArgumentNullException(nameof(entry));
            }

            return await this.cache.AddAsync(entry).ConfigureAwait(false);
        }

        public async Task<bool> Contains(TicketCacheEntry entry)
        {
            var got = await this.cache.GetCacheItemAsync(entry?.Key).ConfigureAwait(false);

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
