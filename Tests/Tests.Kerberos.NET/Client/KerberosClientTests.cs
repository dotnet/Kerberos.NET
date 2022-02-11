// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Linq;
using System.Threading.Tasks;
using Kerberos.NET;
using Kerberos.NET.Client;
using Kerberos.NET.Transport;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class KerberosClientTests
    {
        [TestMethod]
        public void KerberosClientStartup()
        {
            using (var client = new KerberosClient())
            {
                Assert.IsNotNull(client);

                Assert.AreEqual(3, client.Transports.Count());
            }
        }

        [TestMethod]
        public void ServiceTicketsNotCached()
        {
            using (var client = new KerberosClient() { CacheServiceTickets = false })
            {
                Assert.IsNotNull(client.Cache);
                Assert.IsFalse(client.CacheServiceTickets);
            }
        }

        [TestMethod]
        [ExpectedException(typeof(InvalidOperationException))]
        public void CacheCannotBeNull()
        {
            new KerberosClient { Cache = null }.Dispose();
        }

        private class DisposableCache : ITicketCache, IDisposable
        {
            public bool RefreshTickets { get; set; }
            public TimeSpan RefreshInterval { get; set; }
            public string DefaultDomain { get; set; }

            public bool Disposed { get; set; }

            public bool Add(TicketCacheEntry entry)
            {
                throw new NotImplementedException();
            }

            public ValueTask<bool> AddAsync(TicketCacheEntry entry)
            {
                throw new NotImplementedException();
            }

            public bool Contains(TicketCacheEntry entry)
            {
                throw new NotImplementedException();
            }

            public ValueTask<bool> ContainsAsync(TicketCacheEntry entry)
            {
                throw new NotImplementedException();
            }

            public void Dispose()
            {
                this.Disposed = true;
            }

            public object GetCacheItem(string key, string container = null)
            {
                throw new NotImplementedException();
            }

            public T GetCacheItem<T>(string key, string container = null)
            {
                throw new NotImplementedException();
            }

            public ValueTask<object> GetCacheItemAsync(string key, string container = null)
            {
                throw new NotImplementedException();
            }

            public ValueTask<T> GetCacheItemAsync<T>(string key, string container = null)
            {
                throw new NotImplementedException();
            }
        }

        [TestMethod]
        public void CacheSetDisposesCorrectly()
        {
            var disposableCache = new DisposableCache();

            var client = new KerberosClient() { Cache = disposableCache };

            client.Cache = new DisposableCache();

            Assert.IsTrue(disposableCache.Disposed);
        }

        [TestMethod]
        public void TcpTransportEnabledByDefault()
        {
            using (var client = new KerberosClient())
            {
                var tcp = client.Transports.OfType<TcpKerberosTransport>().FirstOrDefault();

                Assert.IsNotNull(tcp);

                Assert.IsTrue(tcp.Enabled);
            }
        }

        [TestMethod]
        public void UdpTransportEnabledByDefault()
        {
            using (var client = new KerberosClient())
            {
                var udp = client.Transports.OfType<UdpKerberosTransport>().FirstOrDefault();

                Assert.IsNotNull(udp);

                Assert.IsTrue(udp.Enabled);
            }
        }

        [TestMethod]
        public void HttpsTransportEnabledByDefault()
        {
            using (var client = new KerberosClient())
            {
                var https = client.Transports.OfType<HttpsKerberosTransport>().FirstOrDefault();

                Assert.IsNotNull(https);

                Assert.IsTrue(https.Enabled);
            }
        }

        [TestMethod]
        [ExpectedException(typeof(InvalidOperationException))]
        public async Task ClientRequestsServiceTicketBeforeAuthentication()
        {
            using (var client = new KerberosClient())
            {
                await client.GetServiceTicket("host/test.com");
            }
        }

        [TestMethod]
        public void CacheFileFormat4Supported()
        {
            using (var client = new KerberosClient())
            {
                Assert.AreEqual(4, client.Configuration.Defaults.CCacheType);
                Assert.IsNotNull(client.Cache);
            }
        }

        [TestMethod]
        public void CacheFileFormatBelow4Supported()
        {
            using (var client = new KerberosClient())
            {
                client.CacheInMemory = false;
                client.Configuration.Defaults.CCacheType = 3;

                Assert.IsNotNull(client.Cache);
            }
        }
    }
}
