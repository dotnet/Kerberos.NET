// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Server;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class KrbKdcRepTests
    {
        private const string LowerCaseRealm1 = "realm.com";
        private const string UpperCaseRealm1 = "REALM.COM";
        private const string LowerCaseRealm2 = "test.com";
        private const string UpperCaseRealm2 = "TEST.COM";

        [TestMethod]
        [ExpectedException(typeof(InvalidOperationException))]
        public void CreateServiceTicket_NullEncPartKey()
        {
            KrbKdcRep.GenerateServiceTicket<KrbTgsRep>(new ServiceTicketRequest
            {
                EncryptedPartKey = null
            });
        }

        [TestMethod]
        [ExpectedException(typeof(InvalidOperationException))]
        public void CreateServiceTicket_NullServicePrincipal()
        {
            var key = KrbEncryptionKey.Generate(EncryptionType.AES128_CTS_HMAC_SHA1_96).AsKey();

            KrbKdcRep.GenerateServiceTicket<KrbTgsRep>(new ServiceTicketRequest
            {
                EncryptedPartKey = key,
                ServicePrincipal = null
            });
        }

        [TestMethod]
        [ExpectedException(typeof(InvalidOperationException))]
        public void CreateServiceTicket_NullServicePrincipalKey()
        {
            var key = KrbEncryptionKey.Generate(EncryptionType.AES128_CTS_HMAC_SHA1_96).AsKey();

            KrbKdcRep.GenerateServiceTicket<KrbTgsRep>(new ServiceTicketRequest
            {
                EncryptedPartKey = key,
                ServicePrincipal = new FakeKerberosPrincipal("blah@blah.com")
            });
        }

        [TestMethod]
        [ExpectedException(typeof(InvalidOperationException))]
        public void CreateServiceTicket_NullPrincipal()
        {
            var key = KrbEncryptionKey.Generate(EncryptionType.AES128_CTS_HMAC_SHA1_96).AsKey();

            KrbKdcRep.GenerateServiceTicket<KrbTgsRep>(new ServiceTicketRequest
            {
                EncryptedPartKey = key,
                ServicePrincipal = new FakeKerberosPrincipal("blah@blah.com"),
                ServicePrincipalKey = key
            });
        }

        [TestMethod]
        public void CreateServiceTicket_NullClientRealmName()
        {
            var key = KrbEncryptionKey.Generate(EncryptionType.AES128_CTS_HMAC_SHA1_96).AsKey();

            // This should not throw, as ClientRealmName is allowed to be null if CompatibilityFlags.IsolateRealmsConsistently is not set
            var tgsRep = KrbKdcRep.GenerateServiceTicket<KrbTgsRep>(new ServiceTicketRequest
            {
                EncryptedPartKey = key,
                ServicePrincipal = new FakeKerberosPrincipal("blah@blah.com"),
                ServicePrincipalKey = key,
                Principal = new FakeKerberosPrincipal("blah@blah2.com"),
                RealmName = "blah.com",
                ClientRealmName = null,
                Compatibility = KerberosCompatibilityFlags.NormalizeRealmsUppercase,
            });
        }

        [TestMethod]
        [ExpectedException(typeof(InvalidOperationException))]
        public void CreateServiceTicket_NullClientRealmName_IsolateRealmsConsistently()
        {
            var key = KrbEncryptionKey.Generate(EncryptionType.AES128_CTS_HMAC_SHA1_96).AsKey();

            var tgsRep = KrbKdcRep.GenerateServiceTicket<KrbTgsRep>(new ServiceTicketRequest
            {
                EncryptedPartKey = key,
                ServicePrincipal = new FakeKerberosPrincipal("blah@blah.com"),
                ServicePrincipalKey = key,
                Principal = new FakeKerberosPrincipal("blah@blah2.com"),
                RealmName = "blah.com",
                ClientRealmName = null,
                Compatibility = KerberosCompatibilityFlags.NormalizeRealmsUppercase | KerberosCompatibilityFlags.IsolateRealmsConsistently,
            });
        }

        [TestMethod]
        public void CreateServiceTicket()
        {
            var key = KrbEncryptionKey.Generate(EncryptionType.AES128_CTS_HMAC_SHA1_96).AsKey();

            var tgsRep = KrbKdcRep.GenerateServiceTicket<KrbTgsRep>(new ServiceTicketRequest
            {
                ClientName = KrbPrincipalName.FromString("blah@test.com"),
                ClientRealmName = "test.com",
                Principal = new FakeKerberosPrincipal("blah@test.com"),

                ServicePrincipal = new FakeKerberosPrincipal("blah@blah.com"),
                ServicePrincipalKey = key,
                RealmName = "blah.com",

                EncryptedPartKey = key,
                Compatibility = KerberosCompatibilityFlags.IsolateRealmsConsistently,
            });

            ValidateTgsRep(
                tgsRep,
                key,
                expectedCName: "blah@test.com",
                expectedCRealm: "test.com",
                expectedSName: "blah@blah.com/blah.com",
                expectedSRealm: "blah.com",
                expectPac: false,
                expectedPacClientName: null);
        }

        [TestMethod]
        public void CreateServiceTicket_ReferralTgtComputerIdentity()
        {
            var key = KrbEncryptionKey.Generate(EncryptionType.AES128_CTS_HMAC_SHA1_96).AsKey();

            var tgsRep = KrbKdcRep.GenerateServiceTicket<KrbTgsRep>(new ServiceTicketRequest
            {
                EncryptedPartKey = key,
                ServicePrincipal = new FakeKerberosPrincipal("blah@blah.com"),
                ServicePrincipalKey = key,
                Principal = new FakeKerberosPrincipal("computer$"),
                RealmName = "blah.com",
                ClientRealmName = "test.com",
                Compatibility = KerberosCompatibilityFlags.IsolateRealmsConsistently,
                IncludePac = true,
                KdcAuthorizationKey = key
            });

            ValidateTgsRep(
                tgsRep,
                key,
                expectedCName: "computer$@test.com",
                expectedCRealm: "test.com",
                expectedSName: "blah@blah.com/blah.com",
                expectedSRealm: "blah.com",
                expectPac: true,
                // Normally PAC client name should be the same as ticket cname. This is fixed when passing in
                // ClientName in the ServiceTicketRequest, see CreateServiceTicket_ReferralTgtComputerIdentity_WithClientName test.
                expectedPacClientName: "computer$");
        }

        [TestMethod]
        public void CreateServiceTicket_ReferralTgtComputerIdentity_WithClientName()
        {
            var key = KrbEncryptionKey.Generate(EncryptionType.AES128_CTS_HMAC_SHA1_96).AsKey();

            var tgsRep = KrbKdcRep.GenerateServiceTicket<KrbTgsRep>(new ServiceTicketRequest
            {
                ClientName = KrbPrincipalName.FromString("computer$@test.com"), // specify client name to get correct PAC client name
                EncryptedPartKey = key,
                ServicePrincipal = new FakeKerberosPrincipal("blah@blah.com"),
                ServicePrincipalKey = key,
                Principal = new FakeKerberosPrincipal("computer$"),
                RealmName = "blah.com",
                ClientRealmName = "test.com",
                Compatibility = KerberosCompatibilityFlags.IsolateRealmsConsistently,
                IncludePac = true,
                KdcAuthorizationKey = key
            });

            ValidateTgsRep(
                tgsRep,
                key,
                expectedCName: "computer$@test.com",
                expectedCRealm: "test.com",
                expectedSName: "blah@blah.com/blah.com",
                expectedSRealm: "blah.com",
                expectPac: true,
                expectedPacClientName: "computer$@test.com");
        }

        [TestMethod]
        // Check that no uppercasing or realm isolation happens by default.
        [DataRow(LowerCaseRealm1, LowerCaseRealm2, KerberosCompatibilityFlags.None, LowerCaseRealm1, LowerCaseRealm1)]
        [DataRow(UpperCaseRealm1, UpperCaseRealm2, KerberosCompatibilityFlags.None, UpperCaseRealm1, UpperCaseRealm1)]
        // Check that KerberosCompatibilityFlags.NormalizeRealmsUppercase uppercases the realm.
        [DataRow(LowerCaseRealm1, LowerCaseRealm2, KerberosCompatibilityFlags.NormalizeRealmsUppercase, UpperCaseRealm1, UpperCaseRealm1)]
        [DataRow(UpperCaseRealm1, UpperCaseRealm2, KerberosCompatibilityFlags.NormalizeRealmsUppercase, UpperCaseRealm1, UpperCaseRealm1)]
        // Check that KerberosCompatibilityFlags.IsolateRealmsConsistently does isolate the realm and crealm
        [DataRow(LowerCaseRealm1, LowerCaseRealm2, KerberosCompatibilityFlags.IsolateRealmsConsistently, LowerCaseRealm1, LowerCaseRealm2)]
        [DataRow(UpperCaseRealm1, UpperCaseRealm2, KerberosCompatibilityFlags.IsolateRealmsConsistently, UpperCaseRealm1, UpperCaseRealm2)]
        // Check that both flags together uppercase and isolate the realms.
        [DataRow(LowerCaseRealm1, LowerCaseRealm2, KerberosCompatibilityFlags.NormalizeRealmsUppercase | KerberosCompatibilityFlags.IsolateRealmsConsistently, UpperCaseRealm1, UpperCaseRealm2)]
        [DataRow(UpperCaseRealm1, UpperCaseRealm2, KerberosCompatibilityFlags.NormalizeRealmsUppercase | KerberosCompatibilityFlags.IsolateRealmsConsistently, UpperCaseRealm1, UpperCaseRealm2)]
        public void CreateServiceTicketOnCompatibilitySetting(
            string realm,
            string crealm,
            KerberosCompatibilityFlags compatibilityFlags,
            string expectedRealm,
            string expectedCRealm
        )
        {
            var cname = $"blah@{crealm}";
            var sname = "blah@blah.com";

            var key = KrbEncryptionKey.Generate(EncryptionType.AES128_CTS_HMAC_SHA1_96).AsKey();

            var tgsRep = KrbKdcRep.GenerateServiceTicket<KrbTgsRep>(new ServiceTicketRequest
            {
                Principal = new FakeKerberosPrincipal(cname),
                ClientName = KrbPrincipalName.FromString(cname),
                ClientRealmName = crealm,

                EncryptedPartKey = key,
                ServicePrincipal = new FakeKerberosPrincipal(sname),
                ServicePrincipalKey = key,
                RealmName = realm,
                Compatibility = compatibilityFlags,

                IncludePac = true,
                KdcAuthorizationKey = key
            });

            ValidateTgsRep(
                tgsRep,
                key,
                expectedCName: cname,
                expectedCRealm: expectedCRealm,
                expectedSName: $"{sname}/{expectedRealm}",
                expectedSRealm: expectedRealm,
                expectPac: true,
                expectedPacClientName: cname);
        }

        private void ValidateTgsRep(
            KrbTgsRep tgsRep,
            KerberosKey ticketKey,
            string expectedCName,
            string expectedCRealm,
            string expectedSName,
            string expectedSRealm,
            bool expectPac,
            string expectedPacClientName)
        {
            Assert.IsNotNull(tgsRep);

            // Check cleartext fields
            Assert.AreEqual(expectedCName, tgsRep.CName.FullyQualifiedName);
            Assert.AreEqual(expectedCRealm, tgsRep.CRealm);
            Assert.AreEqual(expectedSName, tgsRep.Ticket.SName.FullyQualifiedName);
            Assert.AreEqual(expectedSRealm, tgsRep.Ticket.Realm);

            // Check encrypted ticket fields
            var ticketEncPart = tgsRep.Ticket.EncryptedPart.Decrypt(ticketKey, KeyUsage.Ticket, KrbEncTicketPart.DecodeApplication);
            Assert.AreEqual(expectedCName, ticketEncPart.CName.FullyQualifiedName);
            Assert.AreEqual(expectedCRealm, ticketEncPart.CRealm);

            // Check PAC fields
            if (!expectPac)
            {
                Assert.IsFalse(ticketEncPart.TryGetPac(out _));
            }
            else
            {
                bool success = ticketEncPart.TryGetPac(out PrivilegedAttributeCertificate pac);
                Assert.IsTrue(success);
                Assert.IsNotNull(pac);
                Assert.IsNotNull(pac.ClientInformation);
                Assert.AreEqual(expectedPacClientName, pac.ClientInformation.Name);
            }
        }
    }
}
