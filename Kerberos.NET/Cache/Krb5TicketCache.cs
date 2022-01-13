// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using Kerberos.NET.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;

namespace Kerberos.NET.Client
{
    [DebuggerDisplay("{cache}")]
    public class Krb5TicketCache : TicketCacheBase
    {
        private const int E_SHARINGVIOLATION = unchecked((int)0x80070020);
        private readonly string filePath;
        private readonly Krb5CredentialCache cache;

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
            : this(Krb5Config.Default(), logger)
        { }

        protected Krb5TicketCache(Krb5Config config, ILoggerFactory logger)
            : base(config, logger)
        {
            this.cache = new Krb5CredentialCache();
            this.cache.Header[Krb5CredentialCacheTag.KdcClientOffset] = new byte[8];
        }

        public override string DefaultDomain
        {
            get => this.cache?.DefaultPrincipalName?.Realm;
            set { }
        }

        public Krb5CredentialCache Krb5Cache => this.cache;

        public bool PersistChanges { get; set; } = true;

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
            using (var fileHandle = this.OpenFile())
            {
                this.ReadCache(fileHandle);
            }
        }

        private void ReadCache(FileStream fileHandle)
        {
            if (string.IsNullOrWhiteSpace(this.filePath))
            {
                return;
            }

            var cache = new byte[fileHandle.Length];

            int offset = 0;
            int read;

            do
            {
                read = fileHandle.Read(cache, offset, cache.Length - offset);

                offset += read;
            }
            while (read > 0);

            this.ReadCache(cache);
        }

        public override bool Add(TicketCacheEntry entry)
        {
            if (entry == null)
            {
                throw new ArgumentNullException(nameof(entry));
            }

            using (var fileHandle = this.OpenFile(write: this.PersistChanges))
            {
                this.ReadCache(fileHandle);

                this.cache.Add(entry);

                if (this.PersistChanges)
                {
                    this.WriteCache(fileHandle);
                }
            }

            return true;
        }

        private void WriteCache(FileStream fileHandle)
        {
            if (string.IsNullOrWhiteSpace(this.filePath))
            {
                return;
            }

            byte[] bytes = this.Serialize();

            fileHandle.Seek(0, SeekOrigin.Begin);

            fileHandle.Write(bytes, 0, bytes.Length);
            fileHandle.Flush();
        }

        public byte[] Serialize()
        {
            return this.cache.Serialize();
        }

        private FileStream OpenFile(bool write = false)
        {
            var max = 100;

            for (var i = 1; i <= max; i++)
            {
                try
                {
                    if (write)
                    {
                        return File.Open(this.filePath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
                    }
                    else
                    {
                        return File.Open(this.filePath, FileMode.OpenOrCreate, FileAccess.Read, FileShare.Read);
                    }
                }
                catch (IOException ioex)
                {
                    if (i == max)
                    {
                        throw;
                    }

                    if (ioex.HResult == E_SHARINGVIOLATION)
                    {
                        continue;
                    }
                }
            }

            throw null;
        }

        public override object GetCacheItem(string key, string container = null)
        {
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

            using (var fileHandle = this.OpenFile())
            {
                this.ReadCache(fileHandle);

                return this.cache.Contains(entry);
            }
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
