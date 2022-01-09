// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

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
        protected const string AdminFallbackAtCorpUserName = "administrator-fallback@corp.identityintervention.com";
        protected const string TestAtCorpUserName = "testuser@corp.identityintervention.com";
        protected const string FakeAdminAtCorpPassword = "P@ssw0rd!";
        protected const string FakeAppServiceSpn = "host/appservice.corp.identityintervention.com";
        protected const string FakeAppServiceInOtherRealm = "fake/app.otherrealm.identityintervention.com";

        internal static KerberosClient CreateClient(
            KdcListener listener,
            string kdc = null,
            bool caching = true,
            bool queryDns = false,
            bool allowWeakCrypto = false,
            bool useWeakCrypto = false
        )
        {
            KerberosClient client;

            if (listener == null)
            {
                client = new KerberosClient();

                client.PinKdc("corp.identityintervention.com", kdc);
            }
            else
            {
                IKerberosTransport transport = new InMemoryTransport(listener);

                client = new KerberosClient(transports: transport);
            }

            client.Configuration.Defaults.DnsLookupKdc = queryDns;
            client.Configuration.Defaults.AllowWeakCrypto = allowWeakCrypto;
            client.CacheServiceTickets = caching;
            client.RenewTickets = caching;
            client.RenewTicketsThreshold = TimeSpan.MaxValue;
            client.RefreshPollInterval = TimeSpan.FromMilliseconds(10);

            if (useWeakCrypto)
            {
                client.Configuration.Defaults.DefaultTicketEncTypes.Clear();
                client.Configuration.Defaults.DefaultTicketEncTypes.Add(EncryptionType.RC4_HMAC_NT);
            }

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
            KeyAgreementAlgorithm keyAgreement = KeyAgreementAlgorithm.DiffieHellmanModp14,
            bool allowWeakCrypto = false,
            bool useWeakCrypto = false,
            bool mutualAuth = true,
            KrbTicket s4uTicket = null
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

            KerberosClient client = CreateClient(listener, overrideKdc, caching: caching, allowWeakCrypto: allowWeakCrypto, useWeakCrypto: useWeakCrypto);

            using (kerbCred as IDisposable)
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
                        ApOptions = mutualAuth ? ApOptions.MutualRequired : 0
                    }
                );

                await ValidateTicket(ticket, includePac: includePac, spn: spn, mutualAuth: mutualAuth);

                await client.RenewTicket();

                ticket = await client.GetServiceTicket(
                    new RequestServiceTicket
                    {
                        ServicePrincipalName = spn,
                        ApOptions = mutualAuth ? ApOptions.MutualRequired : 0
                    }
                );

                await ValidateTicket(ticket, encodeNego, includePac: includePac, spn: spn, mutualAuth: mutualAuth);

                ticket = await client.GetServiceTicket(
                    new RequestServiceTicket
                    {
                        ServicePrincipalName = spn,
                        ApOptions = mutualAuth ? ApOptions.MutualRequired : 0,
                        S4uTarget = s4u,
                        S4uTicket = s4uTicket
                    }
                );

                await ValidateTicket(ticket, includePac: includePac, spn: spn, mutualAuth: mutualAuth);
            }

            if (user.Contains("-fallback"))
            {
                Assert.AreEqual(PrincipalNameType.NT_PRINCIPAL, kerbCred.PrincipalNameType);
            }
            else
            {
                Assert.AreEqual(PrincipalNameType.NT_ENTERPRISE, kerbCred.PrincipalNameType);
            }
        }

        protected static async Task ValidateTicket(
            ApplicationSessionContext context,
            bool encodeNego = false,
            bool includePac = true,
            string spn = FakeAppServiceSpn,
            bool mutualAuth = true
        )
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

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

            if (mutualAuth)
            {
                var sessionKey = context.AuthenticateServiceResponse(validated.ApRep);

                Assert.IsNotNull(sessionKey);
            }
            else
            {
                Assert.IsNull(validated.ApRep);
            }

            Assert.IsTrue(KerberosCryptoTransformer.AreEqualSlow(context.SessionKey.KeyValue.Span, validated.SessionKey.Span));
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

            using (kerbCred as IDisposable)
            using (client)
            {
                client.PinKdc(kerbCred.Domain, kdc);

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
#pragma warning disable CA1031 // Do not catch general exception types
                        catch (Exception ex)
#pragma warning restore CA1031 // Do not catch general exception types
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
            )
                : base(cert, username)
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
