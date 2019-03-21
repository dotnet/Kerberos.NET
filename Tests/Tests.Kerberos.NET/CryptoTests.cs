using Kerberos.NET;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Kerberos.NET.Entities;
using Kerberos.NET.Crypto;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class CryptoTests : BaseTest
    {
        [TestMethod]
        public async Task TestRC4Kerberos()
        {
            var data = ReadFile("rc4-kerberos-data");
            var key = ReadFile("rc4-key-data");

            await TestDecode(data, key, EncryptionType.RC4_HMAC_NT);
        }

        [TestMethod]
        public async Task TestRC4SPNego()
        {
            var data = ReadFile("rc4-spnego-data");
            var key = ReadFile("rc4-key-data");

            await TestDecode(data, key, EncryptionType.RC4_HMAC_NT);
        }

        [TestMethod]
        public async Task TestAES128Kerberos()
        {
            var data = ReadFile("aes128-kerberos-data");
            var key = ReadFile("aes128-key-data");

            await TestDecode(data, key, EncryptionType.AES128_CTS_HMAC_SHA1_96);
        }

        [TestMethod]
        public async Task TestAES128SPNego()
        {
            var data = ReadFile("aes128-spnego-data");
            var key = ReadFile("aes128-key-data");

            await TestDecode(data, key, EncryptionType.AES128_CTS_HMAC_SHA1_96);
        }

        [TestMethod]
        public async Task TestAES256Kerberos()
        {
            var data = ReadFile("aes256-kerberos-data");
            var key = ReadFile("aes256-key-data");

            await TestDecode(data, key, EncryptionType.AES256_CTS_HMAC_SHA1_96);
        }

        [TestMethod]
        public async Task TestAES256SPNego()
        {
            var data = ReadFile("aes256-spnego-data");
            var key = ReadFile("aes256-key-data");

            await TestDecode(data, key, EncryptionType.AES256_CTS_HMAC_SHA1_96);
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
            public IntrospectiveValidator(byte[] key) : base(key, ticketCache: null)
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
