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
using System.IO;
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
            var tmp = Path.GetTempFileName();
            var cache = new Krb5TicketCache(tmp);

            try
            {
                Assert.IsNotNull(cache);

                cache.Add(new TicketCacheEntry
                {
                    Key = "krbtgt/bar.com",
                    Value = new KerberosClientCacheEntry
                    {
                        KdcResponse = new KrbAsRep
                        {
                            CName = KrbPrincipalName.FromString("user@bar.com"),
                            CRealm = "bar.com",
                            Ticket = new KrbTicket
                            {
                                Realm = "bar.com",
                                SName = KrbPrincipalName.FromString("krbtgt/bar.com"),
                                EncryptedPart = new KrbEncryptedData
                                {
                                    EType = EncryptionType.AES128_CTS_HMAC_SHA1_96,
                                    Cipher = Array.Empty<byte>()
                                }
                            }
                        },
                        SessionKey = KrbEncryptionKey.Generate(EncryptionType.AES128_CTS_HMAC_SHA1_96),
                        SName = KrbPrincipalName.FromString("krbtgt/bar.com")
                    }
                });

                using (var secondCache = new Krb5TicketCache(tmp))
                {
                    var entry = secondCache.GetCacheItem<KerberosClientCacheEntry>("krbtgt/bar.com");

                    Assert.IsNotNull(entry.KdcResponse);
                    Assert.AreEqual("bar.com", entry.KdcResponse.CRealm);
                    Assert.AreEqual("user@bar.com", entry.KdcResponse.CName.FullyQualifiedName);
                }
            }
            finally
            {
                cache.Dispose();

                if (File.Exists(tmp))
                {
                    File.Delete(tmp);
                }
            }
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
    }
}
