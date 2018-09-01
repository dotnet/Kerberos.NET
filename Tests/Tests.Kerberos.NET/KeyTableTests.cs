using System.IO;
using System.Linq;
using Kerberos.NET.Crypto;
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
    }
}
