using Kerberos.NET;
using Kerberos.NET.Crypto;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Threading.Tasks;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class NtlmTests : BaseTest
    {
        private const string NtlmStart = "TlRMTVNTUAABAAAAl4II4gAAAAAAAAAAAAAAAAAAAAAKAO5CAAAADw==";

        private const string SPNegoNtlmStart = "YIGCBgYrBgEFBQKgeDB2oDAwLgYKKwYBBAGCNwICCgYJKoZIgv" +
            "cSAQICBgkqhkiG9xIBAgIGCisGAQQBgjcCAh6iQgRATlRMTVNTUAABAAAAl7II4gkACQA3AAAADwAPACgAAAA" +
            "KAO5CAAAAD0RFU0tUT1AtUThSRTBVRVdPUktHUk9VUA==";

        [TestMethod, ExpectedException(typeof(NotSupportedException))]
        public async Task TestNtlmFirstClassUnsupported()
        {
            var validator = new KerberosValidator(new KerberosKey())
            {
                ValidateAfterDecrypt = DefaultActions
            };

            try
            {
                await validator.Validate(Convert.FromBase64String(NtlmStart));
            }
            catch (NotSupportedException ex)
            {
                Assert.IsTrue(ex.Message.Contains("NTLM"));
                throw;
            }
        }

        [TestMethod, ExpectedException(typeof(NotSupportedException))]
        public async Task TestSPNegoNtlmFirstClassUnsupported()
        {
            var validator = new KerberosValidator(new KerberosKey())
            {
                ValidateAfterDecrypt = DefaultActions
            };

            try
            {
                await validator.Validate(Convert.FromBase64String(SPNegoNtlmStart));
            }
            catch (NotSupportedException ex)
            {
                Assert.IsTrue(ex.Message.Contains("NTLM"));
                throw;
            }
        }
    }
}
