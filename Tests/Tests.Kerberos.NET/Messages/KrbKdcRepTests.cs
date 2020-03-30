using System;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class KrbKdcRepTests
    {
        [TestMethod, ExpectedException(typeof(ArgumentException))]
        public void CreateServiceTicket_NullEncPartKey()
        {
            KrbKdcRep.GenerateServiceTicket<KrbTgsRep>(new ServiceTicketRequest
            {
                EncryptedPartKey = null
            });
        }

        [TestMethod, ExpectedException(typeof(ArgumentException))]
        public void CreateServiceTicket_NullServicePrincipal()
        {
            var key = KrbEncryptionKey.Generate(EncryptionType.AES128_CTS_HMAC_SHA1_96).AsKey();

            KrbKdcRep.GenerateServiceTicket<KrbTgsRep>(new ServiceTicketRequest
            {
                EncryptedPartKey = key,
                ServicePrincipal = null
            });
        }

        [TestMethod, ExpectedException(typeof(ArgumentException))]
        public void CreateServiceTicket_NullServicePrincipalKey()
        {
            var key = KrbEncryptionKey.Generate(EncryptionType.AES128_CTS_HMAC_SHA1_96).AsKey();

            KrbKdcRep.GenerateServiceTicket<KrbTgsRep>(new ServiceTicketRequest
            {
                EncryptedPartKey = key,
                ServicePrincipal = new FakeKerberosPrincipal("blah@blah.com")
            });
        }

        [TestMethod, ExpectedException(typeof(ArgumentException))]
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
    }
}
