using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Kerberos.NET;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class KeyTableTests : BaseTest
    {
        [TestMethod]
        public void Test32BitKeyVersionOverride()
        {
            var keyTable = new KeyTable(ReadDataFile("sample_with_32_bit_version_override.keytab"));

            Assert.IsNotNull(keyTable);
            Assert.AreEqual(2, keyTable.Entries.First().Version);
        }

        [TestMethod]
        public void TestTrailingPadding()
        {
            var keyTable = new KeyTable(ReadDataFile("sample_with_padding.keytab"));

            Assert.IsNotNull(keyTable);
            Assert.AreEqual(15, keyTable.Entries.Count);
            Assert.AreEqual(keyTable.Entries.First().EncryptionType, EncryptionType.DES_CBC_CRC);
            Assert.AreEqual(keyTable.Entries.Last().EncryptionType, EncryptionType.RC4_HMAC_NT);
        }

        [TestMethod]
        public void TestRoundtrip32bOverride()
        {
            var keytable = new KeyTable(ReadDataFile("sample_with_32_bit_version_override.keytab"));

            Assert.IsNotNull(keytable);
            Assert.AreEqual(1, keytable.Entries.Count);

            var buffer = new MemoryStream();

            keytable.Write(new BinaryWriter(buffer));

            var secondKeyTable = new KeyTable(buffer.ToArray());

            Assert.IsNotNull(secondKeyTable);
            Assert.AreEqual(1, secondKeyTable.Entries.Count);

            AssertKeytablesAreEqual(keytable, secondKeyTable);
        }

        [TestMethod]
        public void TestRoundtripTrailingPadding()
        {
            var keytable = new KeyTable(ReadDataFile("sample_with_padding.keytab"));

            Assert.IsNotNull(keytable);
            Assert.AreEqual(15, keytable.Entries.Count);

            var buffer = new MemoryStream();

            keytable.Write(new BinaryWriter(buffer));

            var secondKeyTable = new KeyTable(buffer.ToArray());

            Assert.IsNotNull(secondKeyTable);
            Assert.AreEqual(15, secondKeyTable.Entries.Count);

            AssertKeytablesAreEqual(keytable, secondKeyTable);
        }

        [TestMethod]
        public void TestRoundtripSimple()
        {
            var keytable = new KeyTable(ReadDataFile("sample.keytab"));

            Assert.IsNotNull(keytable);
            Assert.AreEqual(5, keytable.Entries.Count);

            var buffer = new MemoryStream();

            keytable.Write(new BinaryWriter(buffer));

            var secondKeyTable = new KeyTable(buffer.ToArray());

            Assert.IsNotNull(secondKeyTable);
            Assert.AreEqual(5, secondKeyTable.Entries.Count);

            AssertKeytablesAreEqual(keytable, secondKeyTable);
        }

        private static void AssertKeytablesAreEqual(KeyTable keytable, KeyTable secondKeyTable)
        {
            for (var i = 0; i < keytable.Entries.Count; i++)
            {
                Assert.AreEqual(keytable.Entries.ElementAt(i), secondKeyTable.Entries.ElementAt(i));
            }
        }

        [TestMethod]
        public void TestKeyGeneration()
        {
            var keys = new[] {
                new KerberosKey(
                    "password", 
                    new PrincipalName(PrincipalNameType.NT_PRINCIPAL, "REALM.COM", new[] { "host/appservice" }),
                    host: "appservice",
                    etype: EncryptionType.AES256_CTS_HMAC_SHA1_96
                )
            };

            var keytable = new KeyTable(keys);

            var buffer = new MemoryStream();

            keytable.Write(new BinaryWriter(buffer));

            var secondKeytab = new KeyTable(buffer.ToArray());

            AssertKeytablesAreEqual(keytable, secondKeytab);
        }

        [TestMethod]
        public async Task TestAuthenticator_SerializedKeytab()
        {
            var key = new KerberosKey(
                password: "P@ssw0rd!", 
                principalName: new PrincipalName(
                    PrincipalNameType.NT_SRV_INST, 
                    "IDENTITYINTERVENTION.COM", 
                    new[] { "host", "aadg.windows.net.nsatc.net" }
                ), 
                etype: EncryptionType.RC4_HMAC_NT
            );

            var keytab = new KeyTable(key);

            var buffer = new MemoryStream();

            keytab.Write(new BinaryWriter(buffer));

            var secondKeytab = new KeyTable(buffer.ToArray());

            var authenticator = new KerberosAuthenticator(
                new KerberosValidator(secondKeytab)
                {
                    ValidateAfterDecrypt = DefaultActions
                });

            Assert.IsNotNull(authenticator);

            var result = await authenticator.Authenticate(RC4Header);

            Assert.IsNotNull(result);

            Assert.AreEqual("Administrator@identityintervention.com", result.Name);
        }

        [TestMethod]
        public async Task TestAuthenticator_RoundtripKeytab()
        {
            var keytab = new KeyTable(ReadDataFile("sample.keytab"));

            var buffer = new MemoryStream();

            keytab.Write(new BinaryWriter(buffer));

            var secondKeytab = new KeyTable(buffer.ToArray());

            var authenticator = new KerberosAuthenticator(
                new KerberosValidator(secondKeytab)
                {
                    ValidateAfterDecrypt = DefaultActions
                });

            Assert.IsNotNull(authenticator);

            var result = await authenticator.Authenticate(RC4Header);

            Assert.IsNotNull(result);

            Assert.AreEqual("Administrator@identityintervention.com", result.Name);
        }
    }
}
