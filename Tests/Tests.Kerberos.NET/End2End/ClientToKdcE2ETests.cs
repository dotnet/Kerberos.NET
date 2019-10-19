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

namespace Tests.Kerberos.NET

{
    [TestClass]
    public class ClientToKdcE2ETests
    {
        [TestMethod]
        public async Task E2E()
        {
            var port = new Random().Next(20000, 40000);

            var options = new ListenerOptions
            {
                ListeningOn = new IPEndPoint(IPAddress.Loopback, port),
                DefaultRealm = "corp2.identityintervention.com".ToUpper(),
                IsDebug = true,
                RealmLocator = realm => LocateRealm(realm),
                ReceiveTimeout = TimeSpan.FromHours(1)
            };

            using (KdcServiceListener listener = new KdcServiceListener(options))
            {
                _ = listener.Start();

                await RequestAndValidateTickets("administrator@corp.identityintervention.com", "P@ssw0rd!", $"127.0.0.1:{port}");

                listener.Stop();
            }
        }

        [TestMethod]
        public async Task E2EWithCaching()
        {
            var port = new Random().Next(20000, 40000);

            var options = new ListenerOptions
            {
                ListeningOn = new IPEndPoint(IPAddress.Loopback, port),
                DefaultRealm = "corp2.identityintervention.com".ToUpper(),
                IsDebug = true,
                RealmLocator = realm => LocateRealm(realm),
                ReceiveTimeout = TimeSpan.FromHours(1)
            };

            using (KdcServiceListener listener = new KdcServiceListener(options))
            {
                _ = listener.Start();

                await RequestAndValidateTickets("administrator@corp.identityintervention.com", "P@ssw0rd!", $"127.0.0.1:{port}", caching: true);

                listener.Stop();
            }
        }

        [TestMethod]
        public async Task E2EWithNegotiate()
        {
            var port = new Random().Next(20000, 40000);

            var options = new ListenerOptions
            {
                ListeningOn = new IPEndPoint(IPAddress.Loopback, port),
                DefaultRealm = "corp2.identityintervention.com".ToUpper(),
                IsDebug = true,
                RealmLocator = realm => LocateRealm(realm),
                ReceiveTimeout = TimeSpan.FromHours(1)
            };

            using (KdcServiceListener listener = new KdcServiceListener(options))
            {
                _ = listener.Start();

                await RequestAndValidateTickets("administrator@corp.identityintervention.com", "P@ssw0rd!", $"127.0.0.1:{port}", encodeNego: true);

                listener.Stop();
            }
        }

        [TestMethod]
        public async Task E2ES4U()
        {
            var port = new Random().Next(20000, 40000);

            var options = new ListenerOptions
            {
                ListeningOn = new IPEndPoint(IPAddress.Loopback, port),
                DefaultRealm = "corp2.identityintervention.com".ToUpper(),
                IsDebug = true,
                RealmLocator = realm => LocateRealm(realm),
                ReceiveTimeout = TimeSpan.FromHours(1)
            };

            using (KdcServiceListener listener = new KdcServiceListener(options))
            {
                _ = listener.Start();

                await RequestAndValidateTickets("administrator@corp.identityintervention.com", "P@ssw0rd!", $"127.0.0.1:{port}", s4u: "blah@corp.identityintervention.com");

                listener.Stop();
            }
        }

        [TestMethod]
        public async Task U2U()
        {
            var port = new Random().Next(20000, 40000);

            var options = new ListenerOptions
            {
                ListeningOn = new IPEndPoint(IPAddress.Loopback, port),
                DefaultRealm = "corp2.identityintervention.com".ToUpper(),
                IsDebug = true,
                RealmLocator = realm => LocateRealm(realm),
                ReceiveTimeout = TimeSpan.FromHours(1)
            };

            KdcServiceListener listener = new KdcServiceListener(options);

            _ = listener.Start();

            var kerbClientCred = new KerberosPasswordCredential("administrator@corp.identityintervention.com", "P@ssw0rd!");
            var client = new KerberosClient($"127.0.0.1:{port}");

            await client.Authenticate(kerbClientCred);

            var kerbServerCred = new KerberosPasswordCredential("u2u@corp.identityintervention.com", "P@ssw0rd!");
            var server = new KerberosClient($"127.0.0.1:{port}");

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

            Assert.AreEqual("host/u2u/CORP.IDENTITYINTERVENTION.COM", decrypted.SName.FullyQualifiedName);

            listener.Stop();
        }

        [TestMethod, ExpectedException(typeof(TimeoutException))]
        public async Task ReceiveTimeout()
        {
            var port = new Random().Next(20000, 40000);
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
                await RequestAndValidateTickets("administrator@corp.identityintervention.com", "P@ssw0rd!", $"127.0.0.1:{port}");
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
        public async Task E2EMultithreadedClient()
        {
            var port = new Random().Next(20000, 40000);

            var options = new ListenerOptions
            {
                ListeningOn = new IPEndPoint(IPAddress.Loopback, port),
                DefaultRealm = "corp2.identityintervention.com".ToUpper(),
                IsDebug = true,
                RealmLocator = realm => LocateRealm(realm),
                ReceiveTimeout = TimeSpan.FromHours(1)
            };

            using (KdcServiceListener listener = new KdcServiceListener(options))
            {
                _ = listener.Start();

                var exceptions = new List<Exception>();

                var kerbCred = new KerberosPasswordCredential("administrator@corp.identityintervention.com", "P@ssw0rd!");

                string kdc = $"127.0.0.1:{port}";
                //string kdc = "10.0.0.21:88";

                using (KerberosClient client = new KerberosClient(kdc))
                {
                    client.CacheServiceTickets = false;

                    await client.Authenticate(kerbCred);

                    Task.WaitAll(Enumerable.Range(0, 2).Select(taskNum => Task.Run(async () =>
                    {
                        for (var i = 0; i < 100; i++)
                        {
                            try
                            {
                                if (i % 2 == 0)
                                {
                                    await client.Authenticate(kerbCred);
                                }

                                var ticket = await client.GetServiceTicket(new RequestServiceTicket
                                {
                                    ServicePrincipalName = "host/appservice.corp.identityintervention.com",
                                    ApOptions = ApOptions.MutualRequired
                                });

                                Assert.IsNotNull(ticket.ApReq);

                                await ValidateTicket(ticket);
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
            string s4u = null,
            bool encodeNego = false,
            bool caching = false
        )
        {
            var kerbCred = new KerberosPasswordCredential(user, password);

            KerberosClient client = new KerberosClient(overrideKdc) { CacheServiceTickets = caching };

            await client.Authenticate(kerbCred);

            var spn = "host/appservice.corp.identityintervention.com";

            var ticket = await client.GetServiceTicket(
                new RequestServiceTicket
                {
                    ServicePrincipalName = spn,
                    ApOptions = ApOptions.MutualRequired
                }
            );

            await ValidateTicket(ticket);

            await client.RenewTicket();

            ticket = await client.GetServiceTicket(
                new RequestServiceTicket
                {
                    ServicePrincipalName = "host/appservice.corp.identityintervention.com",
                    ApOptions = ApOptions.MutualRequired
                }
            );

            await ValidateTicket(ticket, encodeNego);

            ticket = await client.GetServiceTicket(
                new RequestServiceTicket
                {
                    ServicePrincipalName = "host/appservice.corp.identityintervention.com",
                    ApOptions = ApOptions.MutualRequired,
                    S4uTarget = s4u
                }
            );

            await ValidateTicket(ticket);
        }

        private static async Task ValidateTicket(ApplicationSessionContext context, bool encodeNego = false)
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
                        "P@ssw0rd!",
                        principalName: new PrincipalName(
                            PrincipalNameType.NT_PRINCIPAL,
                            "CORP.IDENTITYINTERVENTION.com",
                            new[] { "host/appservice.corp.identityintervention.com" }
                        ),
                        saltType: SaltType.ActiveDirectoryUser
                    )
                )
            );

            var validated = (KerberosIdentity)await authenticator.Authenticate(encoded);

            Assert.IsNotNull(validated);

            Assert.AreEqual(validated.FindFirst(ClaimTypes.Sid).Value, "S-1-5-123-456-789-12-321-888");

            var sessionKey = context.AuthenticateServiceResponse(validated.ApRep);

            Assert.IsNotNull(sessionKey);
        }

        private static async Task<IRealmService> LocateRealm(string realm, bool slow = false)
        {
            IRealmService service = new FakeRealmService(realm);

            if (slow)
            {
                await Task.Delay(500);
            }

            return service;
        }
    }
}
