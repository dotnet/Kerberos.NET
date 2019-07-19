using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Tests.Kerberos.NET.Data
{
    [TestClass]
    public class KrbErrorTests : BaseTest
    {
        [TestMethod]
        public void TestErrorPreAuthRoundtrip()
        {
            var krbErrBin = ReadDataFile("messages\\krb-error-preauth-required").Skip(4).ToArray();

            var err = KrbError.DecodeAsApplication(krbErrBin);

            var bytes = err.EncodeAsApplication();

            Assert.IsTrue(krbErrBin.SequenceEqual(bytes.ToArray()));
        }

        [TestMethod]
        public void TestKrbErrorParseEtypeInfo()
        {
            var krbErrBin = ReadDataFile("messages\\krb-error-preauth-required").Skip(4).ToArray();

            var err = KrbError.DecodeAsApplication(krbErrBin);

            var preauth = err.DecodePreAuthentication();

            IEnumerable<KrbETypeInfo2Entry> etype = null;

            foreach (var auth in preauth)
            {
                if (auth.Type == PaDataType.PA_ETYPE_INFO2)
                {
                    etype = auth.DecodeETypeInfo2();
                }
            }

            Assert.IsNotNull(etype);

            Assert.AreEqual(2, etype.Count());

            Assert.AreEqual(EncryptionType.AES256_CTS_HMAC_SHA1_96, etype.ElementAt(0).EType);
            Assert.AreEqual(EncryptionType.RC4_HMAC_NT, etype.ElementAt(1).EType);
        }
    }
}
