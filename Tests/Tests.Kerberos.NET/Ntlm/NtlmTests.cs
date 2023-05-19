// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Kerberos.NET;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class NtlmTests : BaseTest
    {
        private const string NtlmStart = "TlRMTVNTUAABAAAAl4II4gAAAAAAAAAAAAAAAAAAAAAKAO5CAAAADw==";

        private const string SPNegoNtlmStart = "YIGCBgYrBgEFBQKgeDB2oDAwLgYKKwYBBAGCNwICCgYJKoZIgv" +
            "cSAQICBgkqhkiG9xIBAgIGCisGAQQBgjcCAh6iQgRATlRMTVNTUAABAAAAl7II4gkACQA3AAAADwAPACgAAAA" +
            "KAO5CAAAAD0RFU0tUT1AtUThSRTBVRVdPUktHUk9VUA==";

        [TestMethod]
        [ExpectedException(typeof(NotSupportedException))]
        public async Task NtlmFirstClassUnsupported()
        {
            var validator = new KerberosValidator(new KerberosKey(key: new byte[16]))
            {
                ValidateAfterDecrypt = DefaultActions
            };

            await validator.Validate(Convert.FromBase64String(NtlmStart));
        }

        [TestMethod]
        [ExpectedException(typeof(NotSupportedException))]
        public async Task SPNegoNtlmFirstClassUnsupported()
        {
            var validator = new KerberosValidator(new KerberosKey(key: new byte[16]))
            {
                ValidateAfterDecrypt = DefaultActions
            };

            await validator.Validate(Convert.FromBase64String(SPNegoNtlmStart));
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void ChoiceEncoding()
        {
            NegotiationToken negToken = new()
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
        public void SPNegoInitTokenRoundtrip()
        {
            NegotiationToken negToken = new()
            {
                InitialToken = new NegTokenInit
                {
                    MechTypes = new Oid[] { new Oid(MechType.NTLM) },
                    MechToken = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7 }
                }
            };

            var encoded = negToken.Encode();

            var decoded = NegotiationToken.Decode(encoded);

            Assert.IsNotNull(decoded);
            Assert.IsNotNull(decoded.InitialToken);
            Assert.IsNull(decoded.ResponseToken);
        }

        [TestMethod]
        public void SPNegoResponseTokenRoundtrip()
        {
            NegotiationToken negToken = new()
            {
                ResponseToken = new NegTokenResp
                {
                    State = NegotiateState.Rejected,
                    SupportedMech = new Oid(MechType.NTLM),
                    ResponseToken = new byte[] { 7, 6, 5, 4, 3, 2, 1, 0 }
                }
            };

            var encoded = negToken.Encode();

            var decoded = NegotiationToken.Decode(encoded);

            Assert.IsNotNull(decoded);
            Assert.IsNull(decoded.InitialToken);
            Assert.IsNotNull(decoded.ResponseToken);
        }
    }
}