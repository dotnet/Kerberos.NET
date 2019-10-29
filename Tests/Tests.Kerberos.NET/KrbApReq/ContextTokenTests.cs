using Kerberos.NET;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class ContextTokenTests
    {
        [TestMethod, ExpectedException(typeof(UnknownMechTypeException))]
        public void GssContextToken_UnknownType()
        {
            var gss = GssApiToken.Encode(new Oid("1.1.1.1.2.3.4.5"), CreateFakeApReq());

            Assert.IsNotNull(gss);

            MessageParser.Parse(gss);
        }

        private static KrbApReq CreateFakeApReq()
        {
            return new KrbApReq
            {
                Authenticator = new KrbEncryptedData { Cipher = new byte[16], EType = EncryptionType.AES128_CTS_HMAC_SHA1_96 },
                Ticket = new KrbTicket
                {
                    EncryptedPart = new KrbEncryptedData { Cipher = new byte[16], EType = EncryptionType.AES128_CTS_HMAC_SHA1_96 },
                    Realm = "test.com",
                    SName = KrbPrincipalName.FromString("host/test.com")
                }
            };
        }
    }
}
