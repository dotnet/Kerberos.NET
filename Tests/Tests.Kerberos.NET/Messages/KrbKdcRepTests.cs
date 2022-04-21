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
        private const string LowerCaseRealm = "realm.com";
        private const string UpperCaseRealm = "REALM.COM";

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

            var ticket = KrbKdcRep.GenerateServiceTicket<KrbTgsRep>(new ServiceTicketRequest
            {
                EncryptedPartKey = key,
                ServicePrincipal = new FakeKerberosPrincipal("blah@blah.com"),
                ServicePrincipalKey = key,
                Principal = new FakeKerberosPrincipal("blah@blah2.com"),
                RealmName = "blah.com"
            });

            Assert.IsNotNull(ticket);
        }

        [DataTestMethod]
        [DataRow(LowerCaseRealm, KerberosCompatibilityFlags.None, LowerCaseRealm)]
        [DataRow(LowerCaseRealm, KerberosCompatibilityFlags.NormalizeRealmsUppercase, UpperCaseRealm)]
        [DataRow(UpperCaseRealm, KerberosCompatibilityFlags.None, UpperCaseRealm)]
        [DataRow(UpperCaseRealm, KerberosCompatibilityFlags.NormalizeRealmsUppercase, UpperCaseRealm)]
        public void CreateServiceTicketOnCompatibilitySetting(string realm, KerberosCompatibilityFlags compatibilityFlags, string expectedRealm)
        {
            var key = KrbEncryptionKey.Generate(EncryptionType.AES128_CTS_HMAC_SHA1_96).AsKey();

            var ticket = KrbKdcRep.GenerateServiceTicket<KrbTgsRep>(new ServiceTicketRequest
            {
                EncryptedPartKey = key,
                ServicePrincipal = new FakeKerberosPrincipal("blah@blah.com"),
                ServicePrincipalKey = key,
                Principal = new FakeKerberosPrincipal("blah@blah2.com"),
                RealmName = realm,
                Compatibility = compatibilityFlags,
            });

            Assert.IsNotNull(ticket);
            Assert.AreEqual(expectedRealm, ticket.CRealm);
        }
    }
}
