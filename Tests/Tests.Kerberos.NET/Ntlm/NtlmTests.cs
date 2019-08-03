using Kerberos.NET;
using Kerberos.NET.Asn1;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Security.Cryptography;
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

            await validator.Validate(Convert.FromBase64String(NtlmStart));
        }

        [TestMethod, ExpectedException(typeof(NotSupportedException))]
        public async Task TestSPNegoNtlmFirstClassUnsupported()
        {
            var validator = new KerberosValidator(new KerberosKey())
            {
                ValidateAfterDecrypt = DefaultActions
            };

            await validator.Validate(Convert.FromBase64String(SPNegoNtlmStart));
        }

        [TestMethod, ExpectedException(typeof(CryptographicException))]
        public void TestChoiceEncoding()
        {
            NegotiationToken negToken = new NegotiationToken
            {
                InitialToken = new NegTokenInit
                {
                    MechTypes = new Oid[] { new Oid(MechType.NTLM) },
                    MechToken = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7 }
                },
                ResponseToken = new NegTokenResp
                {
                    State = NegotiateState.Rejected,
                    SupportedMech = new Oid(MechType.NTLM),
                    ResponseToken = new byte[] { 7, 6, 5, 4, 3, 2, 1, 0 }
                }
            };

            negToken.Encode();
        }

        [TestMethod]
        public void TestSPNegoInitTokenRoundtrip()
        {
            NegotiationToken negToken = new NegotiationToken
            {
                InitialToken = new NegTokenInit
                {
                    MechTypes = new Oid[] { new Oid(MechType.NTLM) },
                    MechToken = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7 }
                }
            };

            var encoded = negToken.Encode();

            var decoded = NegotiationToken.Decode(encoded.AsMemory());

            Assert.IsNotNull(decoded);
            Assert.IsNotNull(decoded.InitialToken);
            Assert.IsNull(decoded.ResponseToken);
        }

        [TestMethod]
        public void TestSPNegoResponseTokenRoundtrip()
        {
            NegotiationToken negToken = new NegotiationToken
            {
                ResponseToken = new NegTokenResp
                {
                    State = NegotiateState.Rejected,
                    SupportedMech = new Oid(MechType.NTLM),
                    ResponseToken = new byte[] { 7, 6, 5, 4, 3, 2, 1, 0 }
                }
            };

            var encoded = negToken.Encode();

            var decoded = NegotiationToken.Decode(encoded.AsMemory());

            Assert.IsNotNull(decoded);
            Assert.IsNull(decoded.InitialToken);
            Assert.IsNotNull(decoded.ResponseToken);
        }
    }
}
