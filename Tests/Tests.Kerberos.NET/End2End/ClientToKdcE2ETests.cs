using Kerberos.NET;
using Kerberos.NET.Client;
using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Server;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Threading.Tasks;
using static Tests.Kerberos.NET.KdcListener;

namespace Tests.Kerberos.NET

{
    [TestClass]
    public class ClientToKdcE2ETests
    {
        private const string AdminAtCorpUserName = "administrator@corp.identityintervention.com";
        private const string FakeAdminAtCorpPassword = "P@ssw0rd!";
        private const string FakeAppServiceSpn = "host/appservice.corp.identityintervention.com";

        private const int ConcurrentThreads = 5;
        private const int RequestsPerThread = 100;

        [TestMethod]
        public async Task E2E()
        {
            var port = NextPort();

            using (var listener = StartListener(port))
            {
                await RequestAndValidateTickets(
                    AdminAtCorpUserName,
                    FakeAdminAtCorpPassword,
                    $"127.0.0.1:{port}"
                );

                listener.Stop();
            }
        }

        [TestMethod]
        public async Task E2E_KeytabCredential()
        {
            var port = NextPort();

            using (var listener = StartListener(port))
            {
                await RequestAndValidateTickets(
                    AdminAtCorpUserName,
                    password: null,
                    $"127.0.0.1:{port}",
                    keytab: new KeyTable(new KerberosKey(FakeAdminAtCorpPassword, etype: EncryptionType.RC4_HMAC_NT))
                );

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

                using (var client = new KerberosClient($"127.0.0.1:{port}"))
                using (var server = new KerberosClient($"127.0.0.1:{port}"))
                {
                    await client.Authenticate(kerbClientCred);

                    await server.Authenticate(kerbClientCred);

                    var serverEntry = await server.Cache.Get<KerberosClientCacheEntry>($"krbtgt/{server.DefaultDomain}");

                    var serverTgt = serverEntry.Ticket.Ticket;

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

        [TestMethod, ExpectedException(typeof(TimeoutException))]
        public async Task ReceiveTimeout()
        {
            var port = NextPort();
            var log = new FakeExceptionLoggerFactory();

            var options = new ListenerOptions
            {
                ListeningOn = new IPEndPoint(IPAddress.Loopback, port),
                DefaultRealm = "corp2.identityintervention.com".ToUpper(),
                IsDebug = true,
                RealmLocator = realm => LocateRealm(realm, slow: true),
                ReceiveTimeout = TimeSpan.FromMilliseconds(1),
                Log = log
            };

            KdcServiceListener listener = new KdcServiceListener(options);

            _ = listener.Start();

            try
            {
                await RequestAndValidateTickets(AdminAtCorpUserName, FakeAdminAtCorpPassword, $"127.0.0.1:{port}");
            }
            catch
            {
            }

            listener.Stop();

            var timeout = log.Exceptions.FirstOrDefault(e => e is TimeoutException);

            Assert.IsNotNull(timeout);

            throw timeout;
        }

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
            string kdc
        )
        {
            using (var listener = StartListener(port))
            {
                var exceptions = new List<Exception>();

                var kerbCred = new KerberosPasswordCredential(AdminAtCorpUserName, FakeAdminAtCorpPassword);

                using (KerberosClient client = new KerberosClient(kdc))
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

        private static async Task RequestAndValidateTickets(
            string user,
            string password,
            string overrideKdc,
            KeyTable keytab = null,
            string s4u = null,
            bool encodeNego = false,
            bool caching = false,
            bool includePac = true
        )
        {
            KerberosCredential kerbCred = null;

            if (keytab == null)
            {
                kerbCred = new KerberosPasswordCredential(user, password);
            }
            else
            {
                kerbCred = new KeytabCredential(user, keytab);
            }

            using (var client = new KerberosClient(overrideKdc) { CacheServiceTickets = caching })
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
