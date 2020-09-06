// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Kerberos.NET.Client
{
    [DebuggerDisplay("{cache}")]
    public class Krb5TicketCache : TicketCacheBase
    {
        private readonly string filePath;
        private readonly Krb5CredentialCache cache;

        private readonly object fileSync = new object();

        public Krb5TicketCache(string filePath, ILoggerFactory logger = null)
            : this(logger)
        {
            this.filePath = Environment.ExpandEnvironmentVariables(filePath);
            this.ReadCache();
        }

        public Krb5TicketCache(byte[] cache, ILoggerFactory logger = null)
            : this(logger)
        {
            this.ReadCache(cache);
        }

        protected Krb5TicketCache(ILoggerFactory logger)
            : base(logger)
        {
            this.cache = new Krb5CredentialCache();
            this.cache.Header[Krb5CredentialCacheTag.KdcClientOffset] = new byte[8];
        }

        public override string DefaultDomain
        {
            get => this.cache?.DefaultPrincipalName?.Realm;
            set { }
        }

        internal IEnumerable<Krb5CredentialCache.Krb5Credential> CacheInternals => this.cache.Credentials;

        private void ReadCache(byte[] cache)
        {
            if (cache == null || cache.Length <= 0)
            {
                return;
            }

            this.cache.Read(cache);
        }

        private void ReadCache()
        {
            if (string.IsNullOrWhiteSpace(this.filePath))
            {
                return;
            }

            using (var file = this.OpenFile())
            {
                var cache = new byte[file.Length];

                int offset = 0, read = 0;

                do
                {
                    read = file.Read(cache, offset, cache.Length - offset);

                    offset += read;
                }
                while (read > 0);

                this.ReadCache(cache);
            }
        }

        public override bool Add(TicketCacheEntry entry)
        {
            if (entry == null)
            {
                throw new ArgumentNullException(nameof(entry));
            }

            this.ReadCache();

            this.cache.Add(entry);

            this.WriteCache();

            return true;
        }

        private void WriteCache()
        {
            if (string.IsNullOrWhiteSpace(this.filePath))
            {
                return;
            }

            lock (this.fileSync)
            {
                using (var stream = this.OpenFile(write: true))
                {
                    byte[] bytes = this.Serialize();

                    stream.Seek(0, SeekOrigin.Begin);

                    stream.Write(bytes, 0, bytes.Length);
                    stream.Flush();
                }
            }
        }

        public byte[] Serialize()
        {
            return this.cache.Serialize();
        }

        private FileStream OpenFile(bool write = false)
        {
            if (write)
            {
                return File.Open(this.filePath, FileMode.Create, FileAccess.Write, FileShare.None);
            }
            else
            {
                return File.Open(this.filePath, FileMode.OpenOrCreate, FileAccess.Read, FileShare.None);
            }
        }

        public override object GetCacheItem(string key, string container = null)
        {
            this.ReadCache();

            return this.cache.GetCacheItem(key);
        }

        public override T GetCacheItem<T>(string key, string container = null)
        {
            if (this.GetCacheItem(key, container) is T result)
            {
                return result;
            }

            return default;
        }

        public override bool Contains(TicketCacheEntry entry)
        {
            if (entry == null)
            {
                throw new ArgumentNullException(nameof(entry));
            }

            this.ReadCache();

            return this.cache.Contains(entry);
        }

        public override ValueTask<bool> AddAsync(TicketCacheEntry entry)
        {
            return new ValueTask<bool>(this.Add(entry));
        }

        public override ValueTask<bool> ContainsAsync(TicketCacheEntry entry)
        {
            return new ValueTask<bool>(this.Contains(entry));
        }

        public override ValueTask<object> GetCacheItemAsync(string key, string container = null)
        {
            return new ValueTask<object>(this.GetCacheItem(key, container));
        }

        public override ValueTask<T> GetCacheItemAsync<T>(string key, string container = null)
        {
            return new ValueTask<T>(this.GetCacheItem<T>(key, container));
        }
    }
}
