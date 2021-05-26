// -----------------------------------------------------------------------
// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using Kerberos.NET.Crypto;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class Rfc6113CryptoTests : BaseCryptoTest
    {
        /*
         Test vectors for RFC 6113 from https://tools.ietf.org/html/rfc6113#appendix-A
         */

        private const string Key1 = "key1";
        private const string Key2 = "key2";
        private static readonly ReadOnlyMemory<byte> A = UnicodeStringToUtf8("a");
        private static readonly ReadOnlyMemory<byte> B = UnicodeStringToUtf8("b");

        [TestInitialize]
        public void Configure()
        {
            // this is important because the built in PBKDF2 implementation blocks salts < 8 bytes
            // so we must use the managed version that doesn't have this restriction
            Rfc2898DeriveBytes.AttemptReflectionLookup = false;
            Rfc2898DeriveBytes.RequireNativeImplementation = false;
        }

        [TestCleanup]
        public void Cleanup()
        {
            Rfc2898DeriveBytes.AttemptReflectionLookup = true;
            Rfc2898DeriveBytes.RequireNativeImplementation = true;
        }

        [TestMethod]
        public void Cf1_ArbitraryString()
        {
            var result = KrbFx.Cf1("x", "y");

            Assert.AreEqual("xy", result);
        }

        [TestMethod]
        public void Cf1_ArbitraryBinary()
        {
            var result = KrbFx.Cf1(new byte[] { 0x1 }, new byte[] { 0x2 });

            AssertArrayEquals(new byte[] { 0x1, 0x2 }, result);
        }

        [TestMethod]
        public void Cf2_Aes128()
        {
            AssertCf2(
                EncryptionType.AES128_CTS_HMAC_SHA1_96,
                "97df97e4b798b29eb31ed7280287a92a",
                Key1,
                Key1,
                Key2,
                Key2,
                A,
                B
            );
        }

        [TestMethod]
        public void Cf2_Aes256()
        {
            AssertCf2(
                EncryptionType.AES256_CTS_HMAC_SHA1_96,
                "4d6ca4e629785c1f01baf55e2e548566b9617ae3a96868c337cb93b5e72b1c7b",
                Key1,
                Key1,
                Key2,
                Key2,
                A,
                B
            );
        }

#if WEAKCRYPTO
        [TestMethod]
        public void Cf2_Rc4()
        {
            AssertCf2(
                EncryptionType.RC4_HMAC_NT,
                "24d7f6b6bae4e5c00d2082c5ebab3672",
                Key1,
                Key1,
                Key2,
                Key2,
                A,
                B
            );
        }
#endif

        private static void AssertCf2(
                EncryptionType etype,
                string expectedStr,
                string key1Str,
                string salt1Str,
                string key2Str,
                string salt2Str,
                ReadOnlyMemory<byte> pepper1,
                ReadOnlyMemory<byte> pepper2
            )
        {
            var expected = HexToByte(expectedStr);

            var handler = CryptoService.CreateTransform(etype);

            var key1 = handler.String2Key(new KerberosKey(key1Str, salt: salt1Str));
            var key2 = handler.String2Key(new KerberosKey(key2Str, salt: salt2Str));

            var result = KrbFx.Cf2(key1, key2, pepper1, pepper2, etype);

            AssertArrayEquals(expected, result);
        }
    }
}
