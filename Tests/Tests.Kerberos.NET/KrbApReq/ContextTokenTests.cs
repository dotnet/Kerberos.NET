// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System.Security.Cryptography;
using Kerberos.NET;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class ContextTokenTests
    {
        [TestMethod]
        [ExpectedException(typeof(UnknownMechTypeException))]
        public void GssContextToken_UnknownType()
        {
            var gss = GssApiToken.Encode(new Oid("1.1.1.1.2.3.4.5"), CreateFakeApReq());

            Assert.IsNotNull(gss);

            MessageParser.Parse(gss);
        }

        [TestMethod]
        [ExpectedException(typeof(UnknownMechTypeException))]
        public void GssContextToken_KerberosBaseNotReal()
        {
            var gss = GssApiToken.Encode(new Oid(MechType.KerberosV5Base), CreateFakeApReq());

            Assert.IsNotNull(gss);

            MessageParser.Parse(gss);
        }

        [TestMethod]
        public void GssContextToken_KerberosMechType()
        {
            var gss = GssApiToken.Encode(new Oid(MechType.KerberosGssApi), CreateFakeApReq());

            Assert.IsNotNull(gss);

            var result = MessageParser.Parse(gss);

            Assert.IsNotNull(result);
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
