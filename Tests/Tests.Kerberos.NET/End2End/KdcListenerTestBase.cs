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
    public abstract class KdcListenerTestBase : BaseTest
    {
        protected const string AdminAtCorpUserName = "administrator@corp.identityintervention.com";
        protected const string TestAtCorpUserName = "testuser@corp.identityintervention.com";
        protected const string FakeAdminAtCorpPassword = "P@ssw0rd!";
        protected const string FakeAppServiceSpn = "host/appservice.corp.identityintervention.com";
        protected const string FakeAppServiceInOtherRealm = "fake/app.otherrealm.identityintervention.com";

        internal static KerberosClient CreateClient(KdcListener listener, string kdc = null, bool caching = true)
        {
            KerberosClient client;

            if (listener == null)
            {
                client = new KerberosClient(kdc: kdc);
            }
            else
            {
                IKerberosTransport transport = new InMemoryTransport(listener);

                client = new KerberosClient(transports: transport);
            }

            client.CacheServiceTickets = caching;
            client.RenewTickets = caching;
            client.RenewTicketsThreshold = TimeSpan.MaxValue;
            client.RefreshPollInterval = TimeSpan.FromMilliseconds(10);

            return client;
        }

        internal static async Task RequestAndValidateTickets(
            KdcListener listener,
            string user,
            string password = null,
            string overrideKdc = null,
            KeyTable keytab = null,
            string s4u = null,
            bool encodeNego = false,
            bool caching = false,
            bool includePac = true,
            X509Certificate2 cert = null,
            string spn = FakeAppServiceSpn,
            KeyAgreementAlgorithm keyAgreement = KeyAgreementAlgorithm.DiffieHellmanModp14
        )
        {
            KerberosCredential kerbCred;

            if (cert != null)
            {
                kerbCred = new TrustedAsymmetricCredential(cert, user) { KeyAgreement = keyAgreement };
            }
            else if (keytab != null)
            {
                kerbCred = new KeytabCredential(user, keytab);
            }
            else
            {
                kerbCred = new KerberosPasswordCredential(user, password);
            }

            KerberosClient client = CreateClient(listener, overrideKdc, caching: caching);

            using (client)
            {
                if (!includePac)
                {
                    client.AuthenticationOptions &= ~AuthenticationOptions.IncludePacRequest;
                }

                await client.Authenticate(kerbCred);

                var ticket = await client.GetServiceTicket(
                    new RequestServiceTicket
                    {
                        ServicePrincipalName = spn,
                        ApOptions = ApOptions.MutualRequired
                    }
                );

                await ValidateTicket(ticket, includePac: includePac, spn: spn);

                await client.RenewTicket();

                ticket = await client.GetServiceTicket(
                    new RequestServiceTicket
                    {
                        ServicePrincipalName = spn,
                        ApOptions = ApOptions.MutualRequired
                    }
                );

                await ValidateTicket(ticket, encodeNego, includePac: includePac, spn: spn);

                ticket = await client.GetServiceTicket(
                    new RequestServiceTicket
                    {
                        ServicePrincipalName = spn,
                        ApOptions = ApOptions.MutualRequired,
                        S4uTarget = s4u
                    }
                );

                await ValidateTicket(ticket, includePac: includePac, spn: spn);
            }
        }

        protected static async Task ValidateTicket(
            ApplicationSessionContext context,
            bool encodeNego = false,
            bool includePac = true,
            string spn = FakeAppServiceSpn
        )
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
                            new[] { spn }
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

        protected static async Task MultithreadedRequests(
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
                List<Exception> exceptions = await MultithreadedRequests(threads, requests, cacheTickets, encodeNego, includePac, kdc, cert, listener);

                if (exceptions.Count > 0)
                {
                    throw new AggregateException($"Failed {exceptions.Count}", exceptions.GroupBy(e => e.GetType()).Select(e => e.First()));
                }
            }
        }

        internal static async Task<List<Exception>> MultithreadedRequests(
            int threads,
            int requests,
            bool cacheTickets,
            bool encodeNego,
            bool includePac,
            string kdc,
            X509Certificate2 cert,
            KdcListener listener
        )
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

            KerberosClient client = CreateClient(listener, kdc);

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

            return exceptions;
        }

        internal class TrustedAsymmetricCredential : KerberosAsymmetricCredential
        {
            public TrustedAsymmetricCredential(
                X509Certificate2 cert, 
                string username = null
            ) : base(cert, username)
            {
                this.IncludeOption = X509IncludeOption.EndCertOnly;
            }

            protected override void VerifyKdcSignature(SignedCms signed)
            {
                signed.CheckSignature(verifySignatureOnly: true);
            }
        }
    }
}
