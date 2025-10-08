// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

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

        [TestMethod]
        public void KdcAsReqHandler_Sync()
        {
            KrbAsRep asRep = RequestTgt(out _, out KrbAsReq asReq);

            Assert.IsNotNull(asRep);

            // RFC 4120 Section 3.1.5 Receipt of KRB_AS_REP Message
            // "If the reply message type is KRB_AS_REP, then the client verifies that the cname and crealm fields in
            // the cleartext portion of the reply match what it requested."
            Assert.AreEqual(Realm, asReq.Body.Realm);
            Assert.AreEqual(Realm, asRep.CRealm);

            Assert.AreEqual(Upn, asReq.Body.CName.FullyQualifiedName);
            Assert.AreEqual(Upn, asRep.CName.FullyQualifiedName);

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
            Assert.AreEqual(Realm, ticketEncPart.CRealm);
            Assert.AreEqual(Upn, ticketEncPart.CName.FullyQualifiedName);
        }

        [TestMethod]
        public void KdcTgsReqHandler_Sync()
        {
            KrbAsRep asRep = RequestTgt(out KrbEncryptionKey tgtKey);

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

        private KrbAsRep RequestTgt(out KrbEncryptionKey sessionKey)
        {
            return RequestTgt(out sessionKey, out _);
        }

        private KrbAsRep RequestTgt(out KrbEncryptionKey sessionKey, out KrbAsReq asReq)
        {
            var cred = new KerberosPasswordCredential(Upn, "P@ssw0rd!")
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
                DefaultRealm = Realm,
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
