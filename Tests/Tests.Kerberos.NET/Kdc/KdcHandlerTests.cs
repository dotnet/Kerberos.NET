// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using Kerberos.NET;
using Kerberos.NET.Client;
using Kerberos.NET.Configuration;
using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Server;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using static Tests.Kerberos.NET.KdcListenerTestBase;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class KdcHandlerTests : BaseTest
    {
        private const string Realm = "CORP2.IDENTITYINTERVENTION.COM";
        private const string Upn = "fake@" + Realm;

        private const string Realm2 = "TEST.COM";
        private const string Upn2WithoutRealm = "fakeuser";
        // private const string Upn2WithoutRealm = "fakeuser@" + Realm2;

        [TestMethod]
        public void KdcAsReqHandler_Sync()
        {
            KrbAsRep asRep = RequestTgt(cname: Upn, crealm: Realm, srealm: Realm, out _, out KrbAsReq asReq);

            ValidateAsRep(asRep, expectedCName: Upn, expectedCRealm: Realm, expectedSRealm: Realm, asReq);
        }

        [TestMethod]
        public void KdcTgsReqHandler_Sync()
        {
            KrbAsRep asRep = RequestTgt(cname: Upn, crealm: Realm, srealm: Realm, out KrbEncryptionKey tgtKey);

            Assert.IsNotNull(asRep);

            var spn = "host/foo." + Realm;

            var tgsReq = KrbTgsReq.CreateTgsReq(
                new RequestServiceTicket
                {
                    Realm = Realm,
                    ServicePrincipalName = spn
                },
                tgtKey,
                asRep,
                out KrbEncryptionKey sessionKey
            );

            var handler = new KdcTgsReqMessageHandler(tgsReq.EncodeApplication(), new KdcServerOptions
            {
                DefaultRealm = Realm,
                IsDebug = true,
                RealmLocator = realm => new FakeRealmService(realm)
            });

            var results = handler.Execute();

            var tgsRep = KrbTgsRep.DecodeApplication(results);

            Assert.IsNotNull(tgsRep);

            var encKdcRepPart = tgsRep.EncPart.Decrypt(
                sessionKey.AsKey(),
                KeyUsage.EncTgsRepPartSubSessionKey,
                d => KrbEncTgsRepPart.DecodeApplication(d)
            );

            Assert.IsNotNull(encKdcRepPart);

            Assert.AreEqual(Realm, tgsRep.CRealm);
            Assert.AreEqual(Upn, tgsRep.CName.FullyQualifiedName);

            // Clients can't decrypt service tickets usually, but for the sake of testing let's check what's inside
            var realmService = new FakeRealmService(Realm);
            var ticketEncPart = realmService.Principals.Find(KrbPrincipalName.FromString(spn)).RetrieveLongTermCredential();

            var serviceTicketEncPart = tgsRep.Ticket.EncryptedPart.Decrypt(
                ticketEncPart,
                KeyUsage.Ticket,
                d => KrbEncTicketPart.DecodeApplication(d)
            );

            Assert.IsNotNull(serviceTicketEncPart);
            Assert.AreEqual(Realm, serviceTicketEncPart.CRealm);
            Assert.AreEqual(Upn, serviceTicketEncPart.CName.FullyQualifiedName);
        }

        [TestMethod]
        public void KdcTgsReqHandler_Sync_ReferralTgt()
        {
            var sourceRealm = Realm2;
            var destRealm = Realm;
            var cname = new KrbPrincipalName
            {
                Type = PrincipalNameType.NT_PRINCIPAL,
                Name = new[] { Upn2WithoutRealm }
            };

            KrbAsRep asRep = CreateReferralTgt(sourceRealm, destRealm, cname, out KerberosKey tgtKey, out KerberosKey asRepKey, out KrbEncryptionKey sessionKey);

            ValidateAsRep(asRep, expectedCName: Upn2WithoutRealm, expectedCRealm: sourceRealm, expectedSRealm: destRealm);

            // Send a TGS-REQ to get a service ticket in the destination realm
            var spn = "host/foo." + Realm;

            var tgsReq = KrbTgsReq.CreateTgsReq(
                new RequestServiceTicket
                {
                    Realm = Realm,
                    ServicePrincipalName = spn
                },
                sessionKey,
                asRep,
                out KrbEncryptionKey subSessionKey
            );

            var handler = new KdcTgsReqMessageHandler(tgsReq.EncodeApplication(), new KdcServerOptions
            {
                DefaultRealm = destRealm,
                IsDebug = true,
                RealmLocator = realm => new FakeRealmService(realm)
            });

            var results = handler.Execute();

            var tgsRep = KrbTgsRep.DecodeApplication(results);

            Assert.IsNotNull(tgsRep);

            var encKdcRepPart = tgsRep.EncPart.Decrypt(
                subSessionKey.AsKey(),
                KeyUsage.EncTgsRepPartSubSessionKey,
                d => KrbEncTgsRepPart.DecodeApplication(d)
            );

            Assert.IsNotNull(encKdcRepPart);

            Assert.AreEqual(sourceRealm, tgsRep.CRealm);
            Assert.AreEqual(Upn2WithoutRealm, tgsRep.CName.FullyQualifiedName);

            // Clients can't decrypt service tickets usually, but for the sake of testing let's check what's inside
            var destRealmService = new FakeRealmService(destRealm);
            var servicePrincipal = destRealmService.Principals.Find(KrbPrincipalName.FromString(spn), destRealm);
            var servicePrincipalKey = servicePrincipal.RetrieveLongTermCredential();

            var ticketEncPart = tgsRep.Ticket.EncryptedPart.Decrypt(
                servicePrincipalKey,
                KeyUsage.Ticket,
                d => KrbEncTicketPart.DecodeApplication(d)
            );

            Assert.IsNotNull(ticketEncPart);
            Assert.AreEqual(sourceRealm, ticketEncPart.CRealm);
            Assert.AreEqual(Upn2WithoutRealm, ticketEncPart.CName.FullyQualifiedName);
        }

        private void ValidateAsRep(KrbAsRep asRep, string expectedCName, string expectedCRealm, string expectedSRealm, KrbAsReq asReq = null)
        {
            Assert.IsNotNull(asRep);

            // RFC 4120 Section 3.1.5 Receipt of KRB_AS_REP Message
            // "If the reply message type is KRB_AS_REP, then the client verifies that the cname and crealm fields in
            // the cleartext portion of the reply match what it requested."
            Assert.AreEqual(MessageType.KRB_AS_REP, asRep.MessageType);
            Assert.AreEqual(expectedCRealm, asRep.CRealm);
            Assert.AreEqual(expectedCName, asRep.CName.FullyQualifiedName);

            // Optionally double check that the AS-REQ also matches
            if (asReq != null)
            {
                Assert.AreEqual(Realm, asReq.Body.Realm);
                Assert.AreEqual(Upn, asReq.Body.CName.FullyQualifiedName);
            }

            // Check that correct TGT was generated
            Assert.AreEqual(expectedSRealm, asRep.Ticket.Realm);
            Assert.AreEqual($"krbtgt/{expectedSRealm}", asRep.Ticket.SName.FullyQualifiedName);

            // Clients can't decrypt TGTs usually, but for the sake of testing let's check what's inside
            var realmService = new FakeRealmService(Realm);
            var tgtPrincipalName = KrbPrincipalName.WellKnown.Krbtgt(Realm);
            var tgtEncPartKey = realmService.Principals.Find(tgtPrincipalName).RetrieveLongTermCredential();

            var ticketEncPart = asRep.Ticket.EncryptedPart.Decrypt(
                tgtEncPartKey,
                KeyUsage.Ticket,
                d => KrbEncTicketPart.DecodeApplication(d)
            );

            Assert.IsNotNull(ticketEncPart);
            Assert.AreEqual(expectedCRealm, ticketEncPart.CRealm);
            Assert.AreEqual(expectedCName, ticketEncPart.CName.FullyQualifiedName);
        }

        private KrbAsRep CreateReferralTgt(string sourceRealm, string destRealm, KrbPrincipalName cname, out KerberosKey tgtKey, out KerberosKey asRepKey, out KrbEncryptionKey sessionKey)
        {
            var sourceRealmService = new FakeRealmService(sourceRealm);

            var sname = KrbPrincipalName.WellKnown.Krbtgt(destRealm);
            var servicePrincipal = sourceRealmService.Principals.Find(sname, destRealm);
            tgtKey = servicePrincipal.RetrieveLongTermCredential();

            var clientPrincipal = sourceRealmService.Principals.Find(cname, sourceRealm);
            asRepKey = clientPrincipal.RetrieveLongTermCredential();

            sessionKey = KrbEncryptionKey.Generate(EncryptionType.AES128_CTS_HMAC_SHA256_128);

            DateTimeOffset now = DateTimeOffset.UtcNow;

            var encTicketPart = new KrbEncTicketPart()
            {
                CName = cname,
                CRealm = sourceRealm,
                Key = sessionKey,
                AuthTime = now,
                StartTime = now,
                EndTime = now.AddHours(1),
                RenewTill = now.AddDays(30),
                Flags = TicketFlags.PreAuthenticated | TicketFlags.Initial | TicketFlags.Renewable | TicketFlags.Forwardable,
                AuthorizationData = null,
                CAddr = new KrbHostAddress[] { },
                Transited = new KrbTransitedEncoding()
            };

            KrbTicket ticket = new KrbTicket()
            {
                Realm = destRealm,
                SName = sname,
                EncryptedPart = KrbEncryptedData.Encrypt(
                    encTicketPart.EncodeApplication(),
                    tgtKey,
                    KeyUsage.Ticket
                )
            };

            KrbEncAsRepPart encAsRepPart = new KrbEncAsRepPart
            {
                AuthTime = encTicketPart.AuthTime,
                StartTime = encTicketPart.AuthTime,
                EndTime = encTicketPart.EndTime,
                RenewTill = encTicketPart.RenewTill,
                KeyExpiration = servicePrincipal.Expires,
                Realm = destRealm,
                SName = sname,
                Flags = encTicketPart.Flags,
                CAddr = encTicketPart.CAddr,
                Key = sessionKey,
                Nonce = 1234567890,
                LastReq = new[] { new KrbLastReq { Type = 0, Value = now } },
                EncryptedPaData = new KrbMethodData
                {
                    MethodData = new[]
                    {
                        new KrbPaData
                        {
                            Type = PaDataType.PA_SUPPORTED_ETYPES,
                            Value = servicePrincipal.SupportedEncryptionTypes.AsReadOnlyMemory(littleEndian: true)
                        }
                    }
                }
            };

            KrbAsRep asRep = new KrbAsRep
            {
                CRealm = Realm2,
                CName = new KrbPrincipalName
                {
                    Type = PrincipalNameType.NT_PRINCIPAL,
                    Name = new[] { Upn2WithoutRealm }
                },
                MessageType = MessageType.KRB_AS_REP,
                Ticket = ticket,
                EncPart = KrbEncryptedData.Encrypt(
                    encAsRepPart.EncodeApplication(),
                    asRepKey,
                    asRepKey.EncryptionType,
                    KeyUsage.EncAsRepPart
                )
            };

            return asRep;
        }

        private KrbAsRep RequestTgt(string cname, string crealm, string srealm, out KrbEncryptionKey sessionKey)
        {
            return RequestTgt(cname, crealm, srealm, out sessionKey, out _);
        }

        private KrbAsRep RequestTgt(string cname, string crealm, string srealm, out KrbEncryptionKey sessionKey, out KrbAsReq asReq)
        {
            var cred = new KerberosPasswordCredential(cname, "P@ssw0rd!", crealm)
            {
                // cheating by skipping the initial leg of requesting PA-type

                Salts = new[]
                {
                    new KeyValuePair<EncryptionType, string>(
                        EncryptionType.AES256_CTS_HMAC_SHA1_96,
                        "CORP.IDENTITYINTERVENTION.COMfake@CORP2.IDENTITYINTERVENTION.COM"
                    )
                },
                Configuration = Krb5Config.Default()
            };

            asReq = KrbAsReq.CreateAsReq(
                cred,
                AuthenticationOptions.AllAuthentication
            );

            var handler = new KdcAsReqMessageHandler(asReq.EncodeApplication(), new KdcServerOptions
            {
                DefaultRealm = srealm,
                IsDebug = true,
                RealmLocator = realm => new FakeRealmService(realm)
            });

            handler.PreAuthHandlers[PaDataType.PA_ENC_TIMESTAMP] = service => new PaDataTimestampHandler(service);

            var results = handler.Execute();

            var decoded = KrbAsRep.DecodeApplication(results);

            var decrypted = cred.DecryptKdcRep(
                decoded,
                KeyUsage.EncAsRepPart,
                d => KrbEncAsRepPart.DecodeApplication(d)
            );

            sessionKey = decrypted.Key;

            return decoded;
        }

        [TestMethod]
        public void AsReqPreAuth_PkinitCertificateAccessible()
        {
            using (var credCert = new X509Certificate2(ReadDataFile("testuser.pfx"), "p"))
            using (var cred = new TrustedAsymmetricCredential(credCert, "user@domain.com"))
            {
                var asReq = KrbAsReq.CreateAsReq(cred, AuthenticationOptions.AllAuthentication);

                var handler = new KdcAsReqMessageHandler(
                    asReq.EncodeApplication(),
                    new KdcServerOptions
                    {
                        DefaultRealm = "corp.identityintervention.com",
                        RealmLocator = realm => new FakeRealmService(realm)
                    });

                handler.PreAuthHandlers[PaDataType.PA_PK_AS_REQ] = service => new PaDataPkAsReqHandler(service)
                {
                    IncludeOption = X509IncludeOption.EndCertOnly
                };

                var context = new PreAuthenticationContext();

                handler.DecodeMessage(context);
                handler.ExecutePreValidate(context);
                handler.QueryPreValidate(context);
                handler.ValidateTicketRequest(context);
                handler.QueryPreExecute(context);
                handler.ExecuteCore(context);

                Assert.AreEqual(PaDataType.PA_PK_AS_REQ, context.ClientAuthority);

                Assert.AreEqual(1, context.PreAuthenticationState.Count);

                Assert.IsTrue(context.PreAuthenticationState.TryGetValue(PaDataType.PA_PK_AS_REQ, out PaDataState paState));

                var state = paState as PkInitState;

                Assert.IsNotNull(state);

                Assert.IsNotNull(state.ClientCertificate);
                Assert.AreEqual(1, state.ClientCertificate.Count);

                var clientCert = state.ClientCertificate[0];

                Assert.IsFalse(clientCert.HasPrivateKey);

                Assert.AreEqual(credCert.Thumbprint, clientCert.Thumbprint);
            }
        }
    }
}
