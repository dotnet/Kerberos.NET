using Kerberos.NET;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Linq;
using System.Threading.Tasks;
using Kerberos.NET.Entities;
using Kerberos.NET.Crypto;
using System;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class CryptoTests : BaseTest
    {
        [TestMethod]
        public async Task TestRC4Kerberos()
        {
            var data = ReadDataFile("rc4-kerberos-data");
            var key = ReadDataFile("rc4-key-data");

            await TestDecode(data, key, EncryptionType.RC4_HMAC_NT);
        }

        [TestMethod]
        public async Task TestRC4SPNego()
        {
            var data = ReadDataFile("rc4-spnego-data");
            var key = ReadDataFile("rc4-key-data");

            await TestDecode(data, key, EncryptionType.RC4_HMAC_NT);
        }

        [TestMethod]
        public async Task TestAES128Kerberos()
        {
            var data = ReadDataFile("aes128-kerberos-data");
            var key = ReadDataFile("aes128-key-data");

            await TestDecode(data, key, EncryptionType.AES128_CTS_HMAC_SHA1_96);
        }

        [TestMethod]
        public async Task TestAES128SPNego()
        {
            var data = ReadDataFile("aes128-spnego-data");
            var key = ReadDataFile("aes128-key-data");

            await TestDecode(data, key, EncryptionType.AES128_CTS_HMAC_SHA1_96);
        }

        [TestMethod]
        public async Task TestAES256Kerberos()
        {
            var data = ReadDataFile("aes256-kerberos-data");
            var key = ReadDataFile("aes256-key-data");

            await TestDecode(data, key, EncryptionType.AES256_CTS_HMAC_SHA1_96);
        }

        [TestMethod]
        public async Task TestAES256SPNego()
        {
            var data = ReadDataFile("aes256-spnego-data");
            var key = ReadDataFile("aes256-key-data");

            await TestDecode(data, key, EncryptionType.AES256_CTS_HMAC_SHA1_96);
        }

        [TestMethod]
        public void TestAes128ADServiceSalt()
        {
            var expectedKey = new byte[] {
                0x8d, 0x5b, 0xaf, 0xed, 0x84, 0xe0, 0xdd, 0x15,
                0xdf, 0xde, 0x34, 0xe8, 0xc0, 0x39, 0x81, 0x39
            };

            AssertSaltGeneration(EncryptionType.AES128_CTS_HMAC_SHA1_96, SaltType.ActiveDirectoryService, expectedKey);
        }

        [TestMethod]
        public void TestAes128ADUserSalt()
        {
            var expectedKey = new byte[] {
                0x0f, 0xbc, 0xd2, 0xcc, 0x43, 0x65, 0x29, 0x13,
                0x1a, 0x78, 0xfa, 0x02, 0xd8, 0x3a, 0x6e, 0xb8
            };

            AssertSaltGeneration(EncryptionType.AES128_CTS_HMAC_SHA1_96, SaltType.ActiveDirectoryUser, expectedKey);
        }

        [TestMethod]
        public void TestAes128Rfc4120Salt()
        {
            var expectedKey = new byte[] {
                0x88, 0xc8, 0xa5, 0xfc, 0xe3, 0x0a, 0x96, 0x97,
                0x46, 0xfe, 0xb5, 0xcb, 0xe6, 0x17, 0xbf, 0xe0
            };

            AssertSaltGeneration(EncryptionType.AES128_CTS_HMAC_SHA1_96, SaltType.Rfc4120, expectedKey);
        }

        [TestMethod]
        public void TestAes256ADServiceSalt()
        {
            var expectedKey = new byte[] {
                0x37, 0x17, 0x8c, 0x78, 0xc2, 0xf4, 0xad, 0xa2,
                0xe0, 0x69, 0x28, 0x01, 0x68, 0x3d, 0x9d, 0xf9,
                0x25, 0x5f, 0x77, 0x52, 0x90, 0xdc, 0x50, 0x4e,
                0xa4, 0x44, 0x14, 0xf7, 0xa4, 0x47, 0xae, 0x94
            };

            AssertSaltGeneration(EncryptionType.AES256_CTS_HMAC_SHA1_96, SaltType.ActiveDirectoryService, expectedKey);
        }

        [TestMethod]
        public void TestAes256ADUserSalt()
        {
            var expectedKey = new byte[] {
                0xb3, 0xf9, 0xca, 0x1b, 0x81, 0xc5, 0x38, 0xe5,
                0x5f, 0x38, 0x4e, 0xe3, 0xc4, 0xec, 0x19, 0x23,
                0xc9, 0x15, 0x47, 0x09, 0x23, 0x90, 0xfe, 0xb0,
                0x63, 0x75, 0xd7, 0x35, 0x26, 0x33, 0xae, 0x81
            };

            AssertSaltGeneration(EncryptionType.AES256_CTS_HMAC_SHA1_96, SaltType.ActiveDirectoryUser, expectedKey);
        }

        [TestMethod]
        public void TestAes256Rfc4120Salt()
        {
            var expectedKey = new byte[] {
                0x0e, 0x1a, 0xff, 0xd8, 0x90, 0xb5, 0x91, 0x2a,
                0x19, 0xa3, 0xa6, 0x79, 0x7e, 0xc7, 0x8b, 0x94,
                0xb8, 0xc2, 0xe7, 0x68, 0x64, 0xa3, 0x82, 0xaf,
                0x6d, 0xe1, 0xa1, 0xcc, 0x80, 0xd0, 0x2d, 0xcd
            };

            AssertSaltGeneration(EncryptionType.AES256_CTS_HMAC_SHA1_96, SaltType.Rfc4120, expectedKey);
        }

        private static void AssertSaltGeneration(EncryptionType etype, SaltType saltType, byte[] expectedKey)
        {
            var key = new KerberosKey(
                "P@ssw0rd!",
                principalName: new PrincipalName(PrincipalNameType.NT_PRINCIPAL, "domain.com", new string[] { "appservice" }),
                host: "appservice",
                etype: etype,
                saltType: saltType
            );

            Assert.AreEqual(saltType, key.SaltFormat);

            var gen = key.GetKey();

            Assert.IsTrue(KerberosCryptoTransformer.AreEqualSlow(gen, expectedKey));
        }

        [TestMethod]
        public void AssertRfc4120CaseSensitivity()
        {
            var lowerCaseKey = new KerberosKey(
                "P@ssw0rd!",
                principalName: new PrincipalName(PrincipalNameType.NT_PRINCIPAL, "domain.com", new string[] { "appservice" }),
                host: "appservice",
                etype: EncryptionType.AES128_CTS_HMAC_SHA1_96,
                saltType: SaltType.Rfc4120
            );

            var lowerCase = lowerCaseKey.GetKey();

            var upperCaseKey = new KerberosKey(
                "P@ssw0rd!",
                principalName: new PrincipalName(PrincipalNameType.NT_PRINCIPAL, "DOMAIN.COM", new string[] { "appservice" }),
                host: "appservice",
                etype: EncryptionType.AES128_CTS_HMAC_SHA1_96,
                saltType: SaltType.Rfc4120
            );

            var upperCase = upperCaseKey.GetKey();

            Assert.IsFalse(KerberosCryptoTransformer.AreEqualSlow(lowerCase, upperCase));
        }

        [TestMethod]
        public void TestMsKileInterop()
        {
            var rawKey = new byte[] {
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
            };

            // DOMAIN.COMhostclient.domain.com
            var key = new KerberosKey(
                password: rawKey,
                host: "client",
                principal: new PrincipalName(PrincipalNameType.NT_PRINCIPAL, "domain.com", new[] { "client" }),
                etype: EncryptionType.AES128_CTS_HMAC_SHA1_96,
                iterationParams: new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xe8 }
            );

            var expectedKey = new byte[] { 0xb8, 0x2e, 0xe1, 0x22, 0x53, 0x1c, 0x2d, 0x94, 0x82, 0x1a, 0xc7, 0x55, 0xbc, 0xcb, 0x58, 0x79 };

            var gen = key.GetKey();

            Assert.IsTrue(KerberosCryptoTransformer.AreEqualSlow(gen, expectedKey));
        }

        [TestMethod]
        public void TestRfc4120Iteration1()
        {
            Rfc4120TestCase(
                iterationCount: 1, 
                password: "password", 
                salt: "ATHENA.MIT.EDUraeburn",
                principal: new PrincipalName(PrincipalNameType.NT_PRINCIPAL, "ATHENA.MIT.EDU", new[] { "raeburn" }),
                aes128key: new byte[] { 0x42, 0x26, 0x3c, 0x6e, 0x89, 0xf4, 0xfc, 0x28, 0xb8, 0xdf, 0x68, 0xee, 0x09, 0x79, 0x9f, 0x15 }, 
                aes256key: new byte[] { 0xfe, 0x69, 0x7b, 0x52, 0xbc, 0x0d, 0x3c, 0xe1, 0x44, 0x32, 0xba, 0x03, 0x6a, 0x92, 0xe6, 0x5b,
                                        0xbb, 0x52, 0x28, 0x09, 0x90, 0xa2, 0xfa, 0x27, 0x88, 0x39, 0x98, 0xd7, 0x2a, 0xf3, 0x01, 0x61 }
            );
        }

        [TestMethod]
        public void TestRfc4120Iteration2()
        {
            Rfc4120TestCase(
                iterationCount: 2,
                password: "password",
                salt: "ATHENA.MIT.EDUraeburn",
                principal: new PrincipalName(PrincipalNameType.NT_PRINCIPAL, "ATHENA.MIT.EDU", new[] { "raeburn" }),
                aes128key: new byte[] { 0xc6, 0x51, 0xbf, 0x29, 0xe2, 0x30, 0x0a, 0xc2, 0x7f, 0xa4, 0x69, 0xd6, 0x93, 0xbd, 0xda, 0x13 },
                aes256key: new byte[] { 0xa2, 0xe1, 0x6d, 0x16, 0xb3, 0x60, 0x69, 0xc1, 0x35, 0xd5, 0xe9, 0xd2, 0xe2, 0x5f, 0x89, 0x61,
                                        0x02, 0x68, 0x56, 0x18, 0xb9, 0x59, 0x14, 0xb4, 0x67, 0xc6, 0x76, 0x22, 0x22, 0x58, 0x24, 0xff }
            );
        }

        [TestMethod]
        public void TestRfc4120Iteration1200()
        {
            Rfc4120TestCase(
                iterationCount: 1200,
                password: "password",
                salt: "ATHENA.MIT.EDUraeburn",
                principal: new PrincipalName(PrincipalNameType.NT_PRINCIPAL, "ATHENA.MIT.EDU", new[] { "raeburn" }),
                aes128key: new byte[] { 0x4c, 0x01, 0xcd, 0x46, 0xd6, 0x32, 0xd0, 0x1e, 0x6d, 0xbe, 0x23, 0x0a, 0x01, 0xed, 0x64, 0x2a },
                aes256key: new byte[] { 0x55, 0xa6, 0xac, 0x74, 0x0a, 0xd1, 0x7b, 0x48, 0x46, 0x94, 0x10, 0x51, 0xe1, 0xe8, 0xb0, 0xa7,
                                        0x54, 0x8d, 0x93, 0xb0, 0xab, 0x30, 0xa8, 0xbc, 0x3f, 0xf1, 0x62, 0x80, 0x38, 0x2b, 0x8c, 0x2a }
            );
        }

        private static void Rfc4120TestCase(
            int iterationCount, 
            string password, 
            string salt, 
            PrincipalName principal,
            byte[] aes128key, 
            byte[] aes256key
        )
        {
            TestRfc4120TestCase(iterationCount, password, salt, principal, aes128key, EncryptionType.AES128_CTS_HMAC_SHA1_96);
            TestRfc4120TestCase(iterationCount, password, salt, principal, aes256key, EncryptionType.AES256_CTS_HMAC_SHA1_96);
        }

        private static void TestRfc4120TestCase(
            int iterationCount, 
            string password, 
            string salt, 
            PrincipalName principal,
            byte[] expectedKey, 
            EncryptionType etype
        )
        {
            byte[] iterations = BitConverter.GetBytes(iterationCount);

            Array.Reverse(iterations);

            var keyFixedSalt = new KerberosKey(
                password: password,
                salt: salt,
                etype: etype,
                iterationParams: iterations
            );

            var fixedKey = keyFixedSalt.GetKey();

            Assert.IsTrue(KerberosCryptoTransformer.AreEqualSlow(fixedKey, expectedKey));

            var keyDerivedSalt = new KerberosKey(
                password: password,
                principalName: principal,
                etype: etype,
                iterationParams: iterations,
                saltType: SaltType.Rfc4120
            );

            var derived = keyDerivedSalt.GetKey();

            Assert.IsTrue(KerberosCryptoTransformer.AreEqualSlow(derived, expectedKey));
        }

        private static async Task TestDecode(byte[] data, byte[] key, EncryptionType etype)
        {
            var validator = new IntrospectiveValidator(key) { ValidateAfterDecrypt = DefaultActions };

            var authenticator = new KerberosAuthenticator(validator);

            var result = await authenticator.Authenticate(data);

            Assert.IsNotNull(result);

            Assert.IsTrue(result.Claims.Count() > 0);

            Assert.AreEqual("Kerberos", result.AuthenticationType);

            Assert.AreEqual("user.test@domain.com", result.Name);

            Assert.IsNotNull(validator.Data);

            Assert.AreEqual(etype, validator.Data.EType);
        }

        private class IntrospectiveValidator : KerberosValidator
        {
            public IntrospectiveValidator(byte[] key)
                : base(key, ticketCache: null)
            {
            }

            public DecryptedData Data { get; set; }

            protected override Task Validate(DecryptedData decryptedToken)
            {
                Data = decryptedToken;

                return base.Validate(decryptedToken);
            }
        }
    }
}
