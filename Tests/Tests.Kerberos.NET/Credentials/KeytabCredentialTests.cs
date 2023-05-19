// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class KeytabCredentialTests
    {
        private static readonly KerberosKey Aes128Key = new("P@ssw0rd!", etype: EncryptionType.AES128_CTS_HMAC_SHA1_96);
        private static readonly KerberosKey RC4Key = new("P@ssw0rd!", etype: EncryptionType.RC4_HMAC_NT);

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void CreateKey_NullCtor()
        {
            new KeytabCredential("sdf", null);
        }

        [TestMethod]
        public void CreateKey()
        {
            var cred = new KeytabCredential("sdfsdf", new KeyTable(), "sdfsdf");

            Assert.IsNotNull(cred);
        }

        [TestMethod]
        public void LocateKey_NoSalts()
        {
            var cred = new KeytabCredential("sdfsdf@domain.com", new KeyTable(Aes128Key, RC4Key));

            var key = cred.CreateKey();

            Assert.IsNotNull(key);

            Assert.AreEqual(EncryptionType.RC4_HMAC_NT, key.EncryptionType);
        }

        [TestMethod]
        public void LocateKey_AesSalts()
        {
            var cred = new KeytabCredential("sdfsdf@domain.com", new KeyTable(Aes128Key, RC4Key))
            {
                Salts = new[] { new KeyValuePair<EncryptionType, string>(EncryptionType.AES128_CTS_HMAC_SHA1_96, "asfsdz") }
            };

            var key = cred.CreateKey();

            Assert.IsNotNull(key);

            Assert.AreEqual(EncryptionType.AES128_CTS_HMAC_SHA1_96, key.EncryptionType);
        }
    }
}