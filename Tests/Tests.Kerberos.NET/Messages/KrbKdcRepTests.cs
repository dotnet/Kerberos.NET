using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Threading.Tasks;

namespace Tests.Kerberos.NET.Messages
{
    [TestClass]
    public class KrbKdcRepTests
    {
        [TestMethod, ExpectedException(typeof(ArgumentException))]
        public async Task CreateServiceTicket_NullEncPartKey()
        {
            await KrbKdcRep.GenerateServiceTicket<KrbTgsRep>(new ServiceTicketRequest
            {
                EncryptedPartKey = null
            });
        }

        [TestMethod, ExpectedException(typeof(ArgumentException))]
        public async Task CreateServiceTicket_NullServicePrincipal()
        {
            var key = KrbEncryptionKey.Generate(EncryptionType.AES128_CTS_HMAC_SHA1_96).AsKey();

            await KrbKdcRep.GenerateServiceTicket<KrbTgsRep>(new ServiceTicketRequest
            {
                EncryptedPartKey = key,
                ServicePrincipal = null
            });
        }

        [TestMethod, ExpectedException(typeof(ArgumentException))]
        public async Task CreateServiceTicket_NullServicePrincipalKey()
        {
            var key = KrbEncryptionKey.Generate(EncryptionType.AES128_CTS_HMAC_SHA1_96).AsKey();

            await KrbKdcRep.GenerateServiceTicket<KrbTgsRep>(new ServiceTicketRequest
            {
                EncryptedPartKey = key,
                ServicePrincipal = new FakeKerberosPrincipal("blah@blah.com")
            });
        }

        [TestMethod, ExpectedException(typeof(ArgumentException))]
        public async Task CreateServiceTicket_NullPrincipal()
        {
            var key = KrbEncryptionKey.Generate(EncryptionType.AES128_CTS_HMAC_SHA1_96).AsKey();

            await KrbKdcRep.GenerateServiceTicket<KrbTgsRep>(new ServiceTicketRequest
            {
                EncryptedPartKey = key,
                ServicePrincipal = new FakeKerberosPrincipal("blah@blah.com"),
                ServicePrincipalKey = key
            });
        }

        [TestMethod]
        public async Task CreateServiceTicket()
        {
            var key = KrbEncryptionKey.Generate(EncryptionType.AES128_CTS_HMAC_SHA1_96).AsKey();

            var ticket = await KrbKdcRep.GenerateServiceTicket<KrbTgsRep>(new ServiceTicketRequest
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
