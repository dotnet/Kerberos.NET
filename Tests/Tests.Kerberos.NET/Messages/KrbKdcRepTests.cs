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
        public void CreateServiceTicket()
        {
            var key = KrbEncryptionKey.Generate(EncryptionType.AES128_CTS_HMAC_SHA1_96).AsKey();

            var tgsRep = KrbKdcRep.GenerateServiceTicket<KrbTgsRep>(new ServiceTicketRequest
            {
                EncryptedPartKey = key,
                ServicePrincipal = new FakeKerberosPrincipal("blah@blah.com"),
                ServicePrincipalKey = key,
                Principal = new FakeKerberosPrincipal("blah@blah2.com"),
                RealmName = "blah.com",
                ClientRealmName = "test.com",
                Compatibility = KerberosCompatibilityFlags.IsolateRealmsConsistently,
            });

            Assert.IsNotNull(tgsRep);
            Assert.AreEqual("blah.com", tgsRep.Ticket.Realm);
            Assert.AreEqual("blah@blah.com/blah.com", tgsRep.Ticket.SName.FullyQualifiedName);
            Assert.AreEqual("test.com", tgsRep.CRealm);
            Assert.AreEqual("blah@blah2.com", tgsRep.CName.FullyQualifiedName);

            var ticketEncPart = tgsRep.Ticket.EncryptedPart.Decrypt(key, KeyUsage.Ticket, KrbEncTicketPart.DecodeApplication);
            Assert.AreEqual("test.com", ticketEncPart.CRealm);
            Assert.AreEqual("blah@blah2.com", ticketEncPart.CName.FullyQualifiedName);
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
            });

            Assert.IsNotNull(tgsRep);
            Assert.AreEqual("blah.com", tgsRep.Ticket.Realm);
            Assert.AreEqual("blah@blah.com/blah.com", tgsRep.Ticket.SName.FullyQualifiedName);
            Assert.AreEqual("test.com", tgsRep.CRealm);
            Assert.AreEqual("computer$@test.com", tgsRep.CName.FullyQualifiedName);

            var ticketEncPart = tgsRep.Ticket.EncryptedPart.Decrypt(key, KeyUsage.Ticket, KrbEncTicketPart.DecodeApplication);
            Assert.AreEqual("test.com", ticketEncPart.CRealm);
            Assert.AreEqual("computer$@test.com", ticketEncPart.CName.FullyQualifiedName);
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
            var key = KrbEncryptionKey.Generate(EncryptionType.AES128_CTS_HMAC_SHA1_96).AsKey();

            var tgsRep = KrbKdcRep.GenerateServiceTicket<KrbTgsRep>(new ServiceTicketRequest
            {
                EncryptedPartKey = key,
                ServicePrincipal = new FakeKerberosPrincipal("blah@blah.com"),
                ServicePrincipalKey = key,
                Principal = new FakeKerberosPrincipal("blah@blah2.com"),
                RealmName = realm,
                ClientRealmName = crealm,
                Compatibility = compatibilityFlags,
            });

            Assert.IsNotNull(tgsRep);
            Assert.AreEqual(expectedRealm, tgsRep.Ticket.Realm);

            var ticketEncPart = tgsRep.Ticket.EncryptedPart.Decrypt(key, KeyUsage.Ticket, KrbEncTicketPart.DecodeApplication);
            Assert.AreEqual(expectedCRealm, ticketEncPart.CRealm);
            Assert.AreEqual(expectedCRealm, tgsRep.CRealm);
        }
    }
}
