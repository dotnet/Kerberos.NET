using Kerberos.NET;
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

            var err = KrbError.DecodeApplication(krbErrBin);

            var bytes = err.EncodeApplication();

            Assert.IsTrue(krbErrBin.SequenceEqual(bytes.ToArray()));
        }

        [TestMethod]
        public void TestKrbErrorParseEtypeInfo()
        {
            var krbErrBin = ReadDataFile("messages\\krb-error-preauth-required").Skip(4).ToArray();

            var err = KrbError.DecodeApplication(krbErrBin);

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

        [TestMethod]
        public void TestKrbErrorRoundtrip()
        {
            var err = new KrbError
            {
                CName = new KrbPrincipalName { Name = new[] { "krbtgt", "domain.com" }, Type = PrincipalNameType.NT_SRV_HST },
                CRealm = "domain.com",
                CTime = DateTimeOffset.UtcNow,
                Cusec = 123,
                EData = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7 },
                ErrorCode = KerberosErrorCode.KRB_ERR_GENERIC,
                EText = "this is a test of the error roundtrip",
                Realm = "domain.com",
                SName = new KrbPrincipalName { Name = new[] { "krbtgt", "domain.com" }, Type = PrincipalNameType.NT_SRV_HST },
                STime = DateTimeOffset.UtcNow,
                Susc = 2345356
            };

            var encoded = err.Encode();

            var decoded = KrbError.DecodeApplication(encoded.AsMemory());

            Assert.IsNotNull(decoded);

            Assert.AreEqual(err.CRealm, decoded.CRealm);
            Assert.AreEqual(MessageType.KRB_ERROR, decoded.MessageType);
            Assert.AreEqual(5, decoded.ProtocolVersionNumber);

            Assert.AreEqual(err.CTime.ToString(), decoded.CTime.ToString());
            Assert.AreEqual(err.ErrorCode, decoded.ErrorCode);
            Assert.AreEqual(err.Realm, decoded.Realm);
        }
    }
}
