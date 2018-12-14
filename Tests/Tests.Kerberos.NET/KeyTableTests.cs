using System.IO;
using System.Linq;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class KeyTableTests
    {
        [TestMethod]
        public void Test32BitKeyVersionOverride()
        {
            var keyTable = new KeyTable(File.ReadAllBytes("data\\sample_with_32_bit_version_override.keytab"));

            Assert.IsNotNull(keyTable);
            Assert.AreEqual(2, keyTable.Entries.First().Version);
        }

        [TestMethod]
        public void TestTrailingPadding()
        {
            var keyTable = new KeyTable(File.ReadAllBytes("data\\sample_with_padding.keytab"));

            Assert.IsNotNull(keyTable);
            Assert.AreEqual(15, keyTable.Entries.Count);
            Assert.AreEqual(keyTable.Entries.First().EncryptionType, EncryptionType.DES_CBC_CRC);
            Assert.AreEqual(keyTable.Entries.Last().EncryptionType, EncryptionType.RC4_HMAC_NT);
        }
    }
}
