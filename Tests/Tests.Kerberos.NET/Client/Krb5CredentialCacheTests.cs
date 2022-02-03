// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using Kerberos.NET;
using Kerberos.NET.Client;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class Krb5CredentialCacheTests : BaseTest
    {
        protected static string FilePath => $"{BasePath}cache\\krb5cc";

        [TestMethod]
        public void ParseFile()
        {
            using (var cache = new Krb5TicketCache(FilePath))
            {
                Assert.IsNotNull(cache);

                AssertCacheFile(cache);
            }
        }

        [TestMethod]
        public void ParseFromBytes()
        {
            var cacheBytes = ReadDataFile("cache\\krb5cc");

            using (var cache = new Krb5TicketCache(cacheBytes))
            {
                Assert.IsNotNull(cacheBytes);

                AssertCacheFile(cache);
            }
        }

        private static void AssertCacheFile(Krb5TicketCache cache)
        {
            var ticket = cache.GetCacheItem<KerberosClientCacheEntry>("krbtgt/IPA.IDENTITYINTERVENTION.COM");

            Assert.IsNotNull(ticket.KdcResponse.Ticket);
            Assert.AreEqual("krbtgt@IPA.IDENTITYINTERVENTION.COM", ticket.KdcResponse.Ticket.SName.FullyQualifiedName);
        }

        [TestMethod]
        public void ParseRoundTrip()
        {
            using (var cache = new Krb5TicketCache(FilePath))
            {
                Assert.IsNotNull(cache);

                var serialized = cache.Serialize();

                var originalBytes = ReadDataFile("cache\\krb5cc");

                Assert.IsTrue(originalBytes.SequenceEqual(serialized));
            }
        }

        [TestMethod]
        public void ParseFileRoundTrip()
        {
            using (var tmp = new TemporaryFile())
            using (var cache = new Krb5TicketCache(tmp.File))
            {

                Assert.IsNotNull(cache);

                cache.Add(CreateCacheEntry());

                using (var secondCache = new Krb5TicketCache(tmp.File))
                {
                    var entry = secondCache.GetCacheItem<KerberosClientCacheEntry>("krbtgt/bar.com");

                    Assert.IsNotNull(entry.KdcResponse);
                    Assert.AreEqual("bar.com", entry.KdcResponse.CRealm);
                    Assert.AreEqual("user@bar.com", entry.KdcResponse.CName.FullyQualifiedName);
                }
            }
        }

        private static TicketCacheEntry CreateCacheEntry(string key = "krbtgt/bar.com")
        {
            return new TicketCacheEntry
            {
                Key = key,
                Value = new KerberosClientCacheEntry
                {
                    KdcResponse = new KrbAsRep
                    {
                        CName = KrbPrincipalName.FromString("user@bar.com"),
                        CRealm = "bar.com",
                        Ticket = new KrbTicket
                        {
                            Realm = "bar.com",
                            SName = KrbPrincipalName.FromString(key),
                            EncryptedPart = new KrbEncryptedData
                            {
                                EType = EncryptionType.AES128_CTS_HMAC_SHA1_96,
                                Cipher = Array.Empty<byte>()
                            }
                        }
                    },
                    SessionKey = KrbEncryptionKey.Generate(EncryptionType.AES128_CTS_HMAC_SHA1_96),
                    SName = KrbPrincipalName.FromString(key)
                }
            };
        }

        [TestMethod]
        public async Task ClientGetsCachedItem()
        {
            using (var client = new KerberosClient() { Cache = new Krb5TicketCache(FilePath) })
            {
                var rep = await client.GetServiceTicket(new RequestServiceTicket
                {
                    ServicePrincipalName = "krbtgt/IPA.IDENTITYINTERVENTION.COM",
                    CanRetrieveExpiredTickets = true
                });

                var apReq = rep.ApReq;

                Assert.IsNotNull(apReq);
                Assert.IsNotNull(apReq.Authenticator);
                Assert.IsNotNull(apReq.Ticket);
                Assert.AreEqual("krbtgt@IPA.IDENTITYINTERVENTION.COM", apReq.Ticket.SName.FullyQualifiedName);
            }
        }

        [TestMethod]
        [ExpectedException(typeof(AggregateException))]
        public async Task ClientCannotGetExpiredCachedItem()
        {
            using (var client = new KerberosClient() { Cache = new Krb5TicketCache(FilePath) })
            {
                await client.GetServiceTicket(new RequestServiceTicket
                {
                    ServicePrincipalName = "krbtgt/IPA.IDENTITYINTERVENTION.COM"
                });
            }
        }

        [TestMethod]
        public void CanConcurrentlyReadCacheFile()
        {
            Parallel.For(0, 1000, _ =>
            {
                using (var cache = new Krb5TicketCache(FilePath))
                {
                    var item = cache.GetCacheItem("krbtgt/IPA.IDENTITYINTERVENTION.COM");

                    Assert.IsNotNull(item);
                }
            });
        }

        [TestMethod]
        public void CanConcurrentReadAndWriteCacheFile()
        {
            using (var tmp = new TemporaryFile())
            {
                Parallel.For(0, 1000, i =>
                {
                    using (var cache = new Krb5TicketCache(tmp.File))
                    {
                        var key = $"krbtgt/IPA-{i}.IDENTITYINTERVENTION.COM";

                        cache.Add(CreateCacheEntry(key));

                        var item = cache.GetCacheItem(key);

                        Assert.IsNotNull(item);
                    }
                });
            }
        }

        [TestMethod]
        public void CanConcurrentReadCacheFileAndWriteToMemory()
        {
            using (var tmp = new TemporaryFile())
            {
                Parallel.For(0, 1000, i =>
                {
                    using (var cache = new Krb5TicketCache(tmp.File) { PersistChanges = false })
                    {
                        var key = $"krbtgt/IPA-{i}.IDENTITYINTERVENTION.COM";

                        cache.Add(CreateCacheEntry(key));

                        var item = cache.GetCacheItem(key);

                        Assert.IsNotNull(item);
                    }
                });
            }
        }

        [TestMethod]
        public void Version3Roundtrips()
        {
            var key = $"krbtgt/IPA.IDENTITYINTERVENTION.COM";

            using (var tmp = new TemporaryFile())
            {
                using (var cache = new Krb5TicketCache(tmp.File) { Version = 3 })
                {
                    cache.Add(CreateCacheEntry(key));
                }

                using (var cache = new Krb5TicketCache(tmp.File))
                {
                    Assert.AreEqual(3, cache.Version);

                    var item = cache.GetCacheItem(key);

                    Assert.IsNotNull(item);
                }
            }
        }
    }
}
