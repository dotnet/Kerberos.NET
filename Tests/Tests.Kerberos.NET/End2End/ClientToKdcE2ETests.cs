using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Kerberos.NET;
using Kerberos.NET.Client;
using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Transport;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using static Tests.Kerberos.NET.KdcListener;

namespace Tests.Kerberos.NET

{
    [TestClass]
    public class ClientToKdcE2ETests : BaseTest
    {
        private const string AdminAtCorpUserName = "administrator@corp.identityintervention.com";
        private const string TestAtCorpUserName = "testuser@corp.identityintervention.com";
        private const string FakeAdminAtCorpPassword = "P@ssw0rd!";
        private const string FakeAppServiceSpn = "host/appservice.corp.identityintervention.com";

        private const int ConcurrentThreads = 2;
        private const int RequestsPerThread = 5;

        [TestMethod]
        public async Task E2E()
        {
            var port = NextPort();

            using (var listener = StartListener(port))
            {
                await RequestAndValidateTickets(
                    listener,
                    AdminAtCorpUserName,
                    FakeAdminAtCorpPassword,
                    $"127.0.0.1:{port}"
                );

                listener.Stop();
            }
        }

        private class TrustedAsymmetricCredential : KerberosAsymmetricCredential
        {
            public TrustedAsymmetricCredential(X509Certificate2 cert, string username = null)
                : base(cert, username)
            {
                this.IncludeOption = X509IncludeOption.EndCertOnly;
            }

            protected override void VerifyKdcSignature(SignedCms signed)
            {
                signed.CheckSignature(verifySignatureOnly: true);
            }
        }

        [TestMethod]
        public async Task E2E_PKINIT()
        {
            var port = NextPort();

            var cert = new X509Certificate2(ReadDataFile("testuser.pfx"), "p");

            using (var listener = StartListener(port))
            {
                await RequestAndValidateTickets(
                    listener,
                    TestAtCorpUserName,
                    overrideKdc: $"127.0.0.1:{port}",
                    cert: cert
                );

                listener.Stop();
            }
        }

        [TestMethod]
        public async Task E2E_PKINIT_Synchronous()
        {
            var port = NextPort();

            var cert = new X509Certificate2(ReadDataFile("testuser.pfx"), "p");

            var requests = RequestsPerThread;

            using (var listener = StartListener(port))
            {
                for (var i = 0; i < requests; i++)
                {
                    await RequestAndValidateTickets(
                        listener,
                        TestAtCorpUserName,
                        overrideKdc: $"127.0.0.1:{port}",
                        cert: cert
                    );
                }

                listener.Stop();
            }
        }

        [TestMethod]
        public async Task E2E_NoPac()
        {
            var port = NextPort();

            using (var listener = StartListener(port))
            {
                await RequestAndValidateTickets(
                    listener,
                    AdminAtCorpUserName,
                    FakeAdminAtCorpPassword,
                    $"127.0.0.1:{port}",
                    includePac: false
                );

                listener.Stop();
            }
        }

        [TestMethod]
        public async Task E2E_WithCaching()
        {
            var port = NextPort();

            using (var listener = StartListener(port))
            {
                await RequestAndValidateTickets(
                    listener,
                    AdminAtCorpUserName,
                    FakeAdminAtCorpPassword,
                    $"127.0.0.1:{port}",
                    caching: true
                );

                listener.Stop();
            }
        }

        [TestMethod]
        public async Task E2E_WithCaching_NoPac()
        {
            var port = NextPort();

            using (var listener = StartListener(port))
            {
                await RequestAndValidateTickets(
                    listener,
                    AdminAtCorpUserName,
                    FakeAdminAtCorpPassword,
                    $"127.0.0.1:{port}",
                    caching: true,
                    includePac: false
                );

                listener.Stop();
            }
        }

        [TestMethod]
        public async Task E2E_WithNegotiate()
        {
            var port = NextPort();

            using (var listener = StartListener(port))
            {
                await RequestAndValidateTickets(
                    listener,
                    AdminAtCorpUserName,
                    FakeAdminAtCorpPassword,
                    $"127.0.0.1:{port}",
                    encodeNego: true
                );

                listener.Stop();
            }
        }

        [TestMethod]
        public async Task E2E_WithNegotiate_NoCache()
        {
            var port = NextPort();

            using (var listener = StartListener(port))
            {
                await RequestAndValidateTickets(
                    listener,
                    AdminAtCorpUserName,
                    FakeAdminAtCorpPassword,
                    $"127.0.0.1:{port}",
                    encodeNego: true,
                    caching: false
                );

                listener.Stop();
            }
        }

        [TestMethod]
        public async Task E2E_WithNegotiate_NoCache_NoPac()
        {
            var port = NextPort();

            using (var listener = StartListener(port))
            {
                await RequestAndValidateTickets(
                    listener,
                    AdminAtCorpUserName,
                    FakeAdminAtCorpPassword,
                    $"127.0.0.1:{port}",
                    encodeNego: true,
                    caching: false,
                    includePac: false
                );

                listener.Stop();
            }
        }

        [TestMethod]
        public async Task E2E_WithNegotiate_NoPac()
        {
            var port = NextPort();

            using (var listener = StartListener(port))
            {
                await RequestAndValidateTickets(
                    listener,
                    AdminAtCorpUserName,
                    FakeAdminAtCorpPassword,
                    $"127.0.0.1:{port}",
                    encodeNego: true,
                    includePac: false
                );

                listener.Stop();
            }
        }

        [TestMethod]
        public async Task E2E_S4U()
        {
            var port = NextPort();

            using (var listener = StartListener(port))
            {
                await RequestAndValidateTickets(
                    listener,
                    AdminAtCorpUserName,
                    FakeAdminAtCorpPassword,
                    $"127.0.0.1:{port}",
                    s4u: "blah@corp.identityintervention.com"
                );

                listener.Stop();
            }
        }

        [TestMethod]
        public async Task E2E_S4U_NoPac()
        {
            var port = NextPort();

            using (var listener = StartListener(port))
            {
                await RequestAndValidateTickets(
                    listener,
                    AdminAtCorpUserName,
                    FakeAdminAtCorpPassword,
                    $"127.0.0.1:{port}",
                    s4u: "blah@corp.identityintervention.com",
                    includePac: false
                );

                listener.Stop();
            }
        }

        [TestMethod]
        public async Task E2E_U2U()
        {
            var port = NextPort();

            using (var listener = StartListener(port))
            {
                var kerbClientCred = new KerberosPasswordCredential(AdminAtCorpUserName, FakeAdminAtCorpPassword);
                var kerbServerCred = new KerberosPasswordCredential("u2u@corp.identityintervention.com", FakeAdminAtCorpPassword);

                var kdc = $"127.0.0.1:{port}";
                
                using (var client = CreateClient(kdc, listener))
                using (var server = CreateClient(kdc, listener))
                {
                    await client.Authenticate(kerbClientCred);

                    await server.Authenticate(kerbClientCred);

                    var serverEntry = await server.Cache.Get<KerberosClientCacheEntry>($"krbtgt/{server.DefaultDomain}");

                    var serverTgt = serverEntry.KdcResponse.Ticket;

                    var apReq = await client.GetServiceTicket("host/u2u", ApOptions.MutualRequired | ApOptions.UseSessionKey, u2uServerTicket: serverTgt);

                    Assert.IsNotNull(apReq);

                    var decrypted = new DecryptedKrbApReq(apReq);

                    Assert.IsNull(decrypted.Ticket);

                    decrypted.Decrypt(serverEntry.SessionKey.AsKey());

                    decrypted.Validate(ValidationActions.All);

                    Assert.IsNotNull(decrypted.Ticket);

                    Assert.AreEqual("host/u2u@CORP.IDENTITYINTERVENTION.COM", decrypted.SName.FullyQualifiedName);
                }

                listener.Stop();
            }
        }

        //[TestMethod, ExpectedException(typeof(TimeoutException))]
        //public async Task ReceiveTimeout()
        //{
        //    var port = NextPort();
        //    var log = new FakeExceptionLoggerFactory();

        //    var options = new ListenerOptions
        //    {
        //        ListeningOn = new IPEndPoint(IPAddress.Loopback, port),
        //        DefaultRealm = "corp2.identityintervention.com".ToUpper(),
        //        IsDebug = true,
        //        RealmLocator = realm => LocateRealm(realm, slow: true),
        //        ReceiveTimeout = TimeSpan.FromMilliseconds(1),
        //        Log = log
        //    };

        //    KdcServiceListener listener = new KdcServiceListener(options);

        //    _ = listener.Start();

        //    try
        //    {
        //        await RequestAndValidateTickets(null, AdminAtCorpUserName, FakeAdminAtCorpPassword, $"127.0.0.1:{port}");
        //    }
        //    catch
        //    {
        //    }

        //    listener.Stop();

        //    var timeout = log.Exceptions.FirstOrDefault(e => e is TimeoutException);

        //    Assert.IsNotNull(timeout);

        //    throw timeout;
        //}

        [TestMethod]
        public async Task E2E_MultithreadedClient()
        {
            var port = NextPort();

            var threads = ConcurrentThreads;
            var requests = RequestsPerThread;

            var cacheTickets = false;
            var encodeNego = false;
            var includePac = false;

            string kdc = $"127.0.0.1:{port}";
            //string kdc = "10.0.0.21:88";

            await MultithreadedRequests(port, threads, requests, cacheTickets, encodeNego, includePac, kdc);
        }

        [TestMethod]
        public async Task E2E_MultithreadedClient_Cache()
        {
            var port = NextPort();

            var threads = ConcurrentThreads;
            var requests = RequestsPerThread;
            var cacheTickets = true;
            var encodeNego = false;
            var includePac = false;

            string kdc = $"127.0.0.1:{port}";
            //string kdc = "10.0.0.21:88";

            await MultithreadedRequests(port, threads, requests, cacheTickets, encodeNego, includePac, kdc);
        }

        [TestMethod]
        public async Task E2E_MultithreadedClient_Cache_Nego()
        {
            var port = NextPort();

            var threads = ConcurrentThreads;
            var requests = RequestsPerThread;
            var cacheTickets = true;
            var encodeNego = true;
            var includePac = false;

            string kdc = $"127.0.0.1:{port}";
            //string kdc = "10.0.0.21:88";

            await MultithreadedRequests(port, threads, requests, cacheTickets, encodeNego, includePac, kdc);
        }

        [TestMethod]
        public async Task E2E_MultithreadedClient_Cache_Nego_Pac()
        {
            var port = NextPort();

            var threads = ConcurrentThreads;
            var requests = RequestsPerThread;
            var cacheTickets = true;
            var encodeNego = true;
            var includePac = true;

            string kdc = $"127.0.0.1:{port}";
            //string kdc = "10.0.0.21:88";

            await MultithreadedRequests(port, threads, requests, cacheTickets, encodeNego, includePac, kdc);
        }

        private static async Task MultithreadedRequests(
            int port,
            int threads,
            int requests,
            bool cacheTickets,
            bool encodeNego,
            bool includePac,
            string kdc,
            X509Certificate2 cert = null
        )
        {
            using (var listener = StartListener(port))
            {
                var exceptions = new List<Exception>();

                KerberosCredential kerbCred;

                if (cert != null)
                {
                    kerbCred = new TrustedAsymmetricCredential(cert, TestAtCorpUserName);
                }
                else
                {
                    kerbCred = new KerberosPasswordCredential(AdminAtCorpUserName, FakeAdminAtCorpPassword);
                }

                KerberosClient client = CreateClient(kdc, listener);

                using (client)
                {
                    client.CacheServiceTickets = cacheTickets;

                    if (!includePac)
                    {
                        client.AuthenticationOptions &= ~AuthenticationOptions.IncludePacRequest;
                    }

                    await client.Authenticate(kerbCred);

                    Task.WaitAll(Enumerable.Range(0, threads).Select(taskNum => Task.Run(async () =>
                    {
                        for (var i = 0; i < requests; i++)
                        {
                            try
                            {
                                if (i % 2 == 0)
                                {
                                    await client.Authenticate(kerbCred);
                                }

                                var ticket = await client.GetServiceTicket(new RequestServiceTicket
                                {
                                    ServicePrincipalName = FakeAppServiceSpn,
                                    ApOptions = ApOptions.MutualRequired
                                });

                                Assert.IsNotNull(ticket.ApReq);

                                await ValidateTicket(ticket, encodeNego: encodeNego, includePac: includePac);
                            }
                            catch (Exception ex)
                            {
                                exceptions.Add(ex);
                            }
                        }
                    })).ToArray());
                }

                listener.Stop();

                if (exceptions.Count > 0)
                {
                    throw new AggregateException($"Failed {exceptions.Count}", exceptions.GroupBy(e => e.GetType()).Select(e => e.First()));
                }
            }
        }

        private static KerberosClient CreateClient(string kdc, KdcListener listener)
        {
            KerberosClient client;

            if (listener == null)
            {
                throw new Exception();
            }
            else
            {
                IKerberosTransport transport = new InMemoryTransport(listener);

                client = new KerberosClient(transports: transport);
            }

            return client;
        }

        private static async Task RequestAndValidateTickets(
            KdcListener listener,
            string user,
            string password = null,
            string overrideKdc = null,
            KeyTable keytab = null,
            string s4u = null,
            bool encodeNego = false,
            bool caching = false,
            bool includePac = true,
            X509Certificate2 cert = null
        )
        {
            KerberosCredential kerbCred;

            if (cert != null)
            {
                kerbCred = new TrustedAsymmetricCredential(cert, user);
            }
            else if (keytab != null)
            {
                kerbCred = new KeytabCredential(user, keytab);
            }
            else
            {
                kerbCred = new KerberosPasswordCredential(user, password);
            }

            KerberosClient client = CreateClient(overrideKdc, listener);

            using (client)
            {
                if (!includePac)
                {
                    client.AuthenticationOptions &= ~AuthenticationOptions.IncludePacRequest;
                }

                await client.Authenticate(kerbCred);

                var spn = FakeAppServiceSpn;

                var ticket = await client.GetServiceTicket(
                    new RequestServiceTicket
                    {
                        ServicePrincipalName = spn,
                        ApOptions = ApOptions.MutualRequired
                    }
                );

                await ValidateTicket(ticket, includePac: includePac);

                await client.RenewTicket();

                ticket = await client.GetServiceTicket(
                    new RequestServiceTicket
                    {
                        ServicePrincipalName = FakeAppServiceSpn,
                        ApOptions = ApOptions.MutualRequired
                    }
                );

                await ValidateTicket(ticket, encodeNego, includePac: includePac);

                ticket = await client.GetServiceTicket(
                    new RequestServiceTicket
                    {
                        ServicePrincipalName = FakeAppServiceSpn,
                        ApOptions = ApOptions.MutualRequired,
                        S4uTarget = s4u
                    }
                );

                await ValidateTicket(ticket, includePac: includePac);
            }
        }

        private static async Task ValidateTicket(ApplicationSessionContext context, bool encodeNego = false, bool includePac = true)
        {
            var ticket = context.ApReq;

            byte[] encoded;

            if (encodeNego)
            {
                encoded = ticket.EncodeGssApi().ToArray();
            }
            else
            {
                encoded = ticket.EncodeApplication().ToArray();
            }

            var authenticator = new KerberosAuthenticator(
                new KeyTable(
                    new KerberosKey(
                        FakeAdminAtCorpPassword,
                        principalName: new PrincipalName(
                            PrincipalNameType.NT_PRINCIPAL,
                            "CORP.IDENTITYINTERVENTION.com",
                            new[] { FakeAppServiceSpn }
                        ),
                        saltType: SaltType.ActiveDirectoryUser
                    )
                )
            );

            var validated = (KerberosIdentity)await authenticator.Authenticate(encoded);

            Assert.IsNotNull(validated);

            var sidClaim = validated.FindFirst(ClaimTypes.Sid);

            if (includePac)
            {
                Assert.AreEqual("S-1-5-123-456-789-12-321-888", sidClaim?.Value);
            }
            else
            {
                Assert.IsNull(sidClaim);
            }

            var sessionKey = context.AuthenticateServiceResponse(validated.ApRep);

            Assert.IsNotNull(sessionKey);
        }
    }
}
