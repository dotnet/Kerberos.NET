// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Text;
using Kerberos.NET.Client;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class KrbSafePrivTests : BaseTest
    {
        private static KerberosKey GenerateKey()
        {
            return KrbEncryptionKey.Generate(EncryptionType.AES256_CTS_HMAC_SHA1_96).AsKey();
        }

        private static KrbHostAddress CreateLocalhostAddress()
        {
            return new KrbHostAddress
            {
                AddressType = AddressType.IPv4,
                Address = new byte[] { 127, 0, 0, 1 }
            };
        }

        [TestMethod]
        public void KrbSafe_Create_Verify_RoundTrip()
        {
            var key = GenerateKey();
            var userData = Encoding.UTF8.GetBytes("hello kerberos");
            var sender = CreateLocalhostAddress();

            var safe = KrbSafe.Create(userData, key, sender);

            var result = safe.Verify(key);

            CollectionAssert.AreEqual(userData, result.ToArray());
        }

        [TestMethod]
        [ExpectedException(typeof(Exception), AllowDerivedTypes = true)]
        public void KrbSafe_Verify_WrongKey_Throws()
        {
            var key = GenerateKey();
            var wrongKey = GenerateKey();
            var userData = Encoding.UTF8.GetBytes("secret data");
            var sender = CreateLocalhostAddress();

            var safe = KrbSafe.Create(userData, key, sender);

            safe.Verify(wrongKey);
        }

        [TestMethod]
        public void KrbSafe_Create_SetsProtocolFields()
        {
            var key = GenerateKey();
            var userData = Encoding.UTF8.GetBytes("test");
            var sender = CreateLocalhostAddress();

            var safe = KrbSafe.Create(userData, key, sender);

            Assert.AreEqual(5, safe.ProtocolVersionNumber);
            Assert.AreEqual(MessageType.KRB_SAFE, safe.MessageType);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void KrbSafe_Create_NullKey_Throws()
        {
            var userData = Encoding.UTF8.GetBytes("test");
            var sender = CreateLocalhostAddress();

            KrbSafe.Create(userData, null, sender);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void KrbSafe_Verify_NullKey_Throws()
        {
            var key = GenerateKey();
            var userData = Encoding.UTF8.GetBytes("test");
            var sender = CreateLocalhostAddress();

            var safe = KrbSafe.Create(userData, key, sender);

            safe.Verify(null);
        }

        [TestMethod]
        public void KrbPriv_Create_Decrypt_RoundTrip()
        {
            var key = GenerateKey();
            var userData = Encoding.UTF8.GetBytes("confidential payload");
            var sender = CreateLocalhostAddress();

            var privPart = new KrbEncKrbPrivPart
            {
                UserData = userData,
                Timestamp = DateTimeOffset.UtcNow,
                Usec = 0,
                SeqNumber = 1,
                SAddress = sender
            };

            var priv = KrbPriv.Create(key, privPart);

            var decrypted = priv.Decrypt(key);

            CollectionAssert.AreEqual(userData, decrypted.UserData.ToArray());
        }

        [TestMethod]
        [ExpectedException(typeof(Exception), AllowDerivedTypes = true)]
        public void KrbPriv_Decrypt_WrongKey_Throws()
        {
            var key = GenerateKey();
            var wrongKey = GenerateKey();
            var userData = Encoding.UTF8.GetBytes("confidential");
            var sender = CreateLocalhostAddress();

            var privPart = new KrbEncKrbPrivPart
            {
                UserData = userData,
                Timestamp = DateTimeOffset.UtcNow,
                Usec = 0,
                SeqNumber = 1,
                SAddress = sender
            };

            var priv = KrbPriv.Create(key, privPart);

            priv.Decrypt(wrongKey);
        }

        [TestMethod]
        public void KrbPriv_Create_SetsProtocolFields()
        {
            var key = GenerateKey();
            var userData = Encoding.UTF8.GetBytes("test");
            var sender = CreateLocalhostAddress();

            var privPart = new KrbEncKrbPrivPart
            {
                UserData = userData,
                Timestamp = DateTimeOffset.UtcNow,
                Usec = 0,
                SeqNumber = 1,
                SAddress = sender
            };

            var priv = KrbPriv.Create(key, privPart);

            Assert.AreEqual(5, priv.ProtocolVersionNumber);
            Assert.AreEqual(MessageType.KRB_PRIV, priv.MessageType);
        }

        [TestMethod]
        public void KerberosMessageService_MakeSafe_VerifySafe_RoundTrip()
        {
            var key = GenerateKey();
            var localAddr = CreateLocalhostAddress();
            var remoteAddr = new KrbHostAddress
            {
                AddressType = AddressType.IPv4,
                Address = new byte[] { 10, 0, 0, 1 }
            };

            var service = new KerberosMessageService(key, localAddr, remoteAddr);

            var userData = Encoding.UTF8.GetBytes("safe message");

            var safe = service.MakeSafe(userData);
            var result = service.VerifySafe(safe);

            CollectionAssert.AreEqual(userData, result.ToArray());
        }

        [TestMethod]
        public void KerberosMessageService_MakePriv_DecryptPriv_RoundTrip()
        {
            var key = GenerateKey();
            var localAddr = CreateLocalhostAddress();
            var remoteAddr = new KrbHostAddress
            {
                AddressType = AddressType.IPv4,
                Address = new byte[] { 10, 0, 0, 1 }
            };

            var service = new KerberosMessageService(key, localAddr, remoteAddr);

            var userData = Encoding.UTF8.GetBytes("private message");

            var priv = service.MakePriv(userData);
            var result = service.DecryptPriv(priv);

            CollectionAssert.AreEqual(userData, result.ToArray());
        }

        [TestMethod]
        public void KerberosMessageService_SequenceNumberIncrements()
        {
            var key = GenerateKey();
            var localAddr = CreateLocalhostAddress();

            var service = new KerberosMessageService(key, localAddr, initialSequenceNumber: 10);

            var safe1 = service.MakeSafe(Encoding.UTF8.GetBytes("msg1"));
            var safe2 = service.MakeSafe(Encoding.UTF8.GetBytes("msg2"));

            Assert.AreEqual(10, safe1.SafeBody.SeqNumber);
            Assert.AreEqual(11, safe2.SafeBody.SeqNumber);
        }
    }
}
