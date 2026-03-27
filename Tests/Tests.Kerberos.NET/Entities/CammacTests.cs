// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class CammacTests : BaseTest
    {
        private static KrbAuthorizationData[] CreateTestElements()
        {
            return new[]
            {
                new KrbAuthorizationData
                {
                    Type = AuthorizationDataType.AdIfRelevant,
                    Data = new byte[] { 1, 2, 3 }
                }
            };
        }

        private static KerberosKey GenerateKey()
        {
            var keyData = KrbEncryptionKey.Generate(EncryptionType.AES256_CTS_HMAC_SHA1_96);
            return keyData.AsKey();
        }

        [TestMethod]
        public void KrbAdCammac_Create_WithKdcKeyOnly()
        {
            var elements = CreateTestElements();
            var kdcKey = GenerateKey();

            var cammac = KrbAdCammac.Create(elements, kdcKey);

            Assert.IsNotNull(cammac.Elements);
            Assert.AreEqual(1, cammac.Elements.Length);
            Assert.IsNotNull(cammac.KdcVerifier);
            Assert.IsNull(cammac.ServiceVerifier);
        }

        [TestMethod]
        public void KrbAdCammac_Create_WithBothKeys()
        {
            var elements = CreateTestElements();
            var kdcKey = GenerateKey();
            var serviceKey = GenerateKey();

            var cammac = KrbAdCammac.Create(elements, kdcKey, serviceKey);

            Assert.IsNotNull(cammac.Elements);
            Assert.AreEqual(1, cammac.Elements.Length);
            Assert.IsNotNull(cammac.KdcVerifier);
            Assert.IsNotNull(cammac.ServiceVerifier);
        }

        [TestMethod]
        public void KrbAdCammac_ValidateKdcVerifier_Success()
        {
            var elements = CreateTestElements();
            var kdcKey = GenerateKey();

            var cammac = KrbAdCammac.Create(elements, kdcKey);

            Assert.IsTrue(cammac.ValidateKdcVerifier(kdcKey));
        }

        [TestMethod]
        public void KrbAdCammac_ValidateKdcVerifier_WrongKey_Fails()
        {
            var elements = CreateTestElements();
            var kdcKey = GenerateKey();
            var wrongKey = GenerateKey();

            var cammac = KrbAdCammac.Create(elements, kdcKey);

            Assert.IsFalse(cammac.ValidateKdcVerifier(wrongKey));
        }

        [TestMethod]
        public void KrbAdCammac_ValidateServiceVerifier_Success()
        {
            var elements = CreateTestElements();
            var kdcKey = GenerateKey();
            var serviceKey = GenerateKey();

            var cammac = KrbAdCammac.Create(elements, kdcKey, serviceKey);

            Assert.IsTrue(cammac.ValidateServiceVerifier(serviceKey));
        }

        [TestMethod]
        public void KrbAdCammac_ValidateServiceVerifier_NullVerifier_ReturnsFalse()
        {
            var elements = CreateTestElements();
            var kdcKey = GenerateKey();

            var cammac = KrbAdCammac.Create(elements, kdcKey);

            Assert.IsFalse(cammac.ValidateServiceVerifier(GenerateKey()));
        }

        [TestMethod]
        public void KrbAdCammac_ToAuthorizationData()
        {
            var elements = CreateTestElements();
            var kdcKey = GenerateKey();

            var cammac = KrbAdCammac.Create(elements, kdcKey);
            var authData = cammac.ToAuthorizationData();

            Assert.AreEqual(AuthorizationDataType.AdCammac, authData.Type);
            Assert.IsTrue(authData.Data.Length > 0);
        }

        [TestMethod]
        public void KrbAdCammac_Encode_Decode_RoundTrip()
        {
            var elements = CreateTestElements();
            var kdcKey = GenerateKey();
            var serviceKey = GenerateKey();

            var cammac = KrbAdCammac.Create(elements, kdcKey, serviceKey);

            var encoded = cammac.Encode();
            var decoded = KrbAdCammac.Decode(encoded);

            Assert.IsNotNull(decoded.Elements);
            Assert.AreEqual(cammac.Elements.Length, decoded.Elements.Length);
            Assert.IsNotNull(decoded.KdcVerifier);
            Assert.IsNotNull(decoded.ServiceVerifier);

            Assert.IsTrue(decoded.ValidateKdcVerifier(kdcKey));
            Assert.IsTrue(decoded.ValidateServiceVerifier(serviceKey));
        }

        [TestMethod]
        public void KrbVerifierMac_Encode_Decode_RoundTrip()
        {
            var kdcKey = GenerateKey();
            var elements = CreateTestElements();

            var cammac = KrbAdCammac.Create(elements, kdcKey);
            var verifier = cammac.KdcVerifier;

            var encoded = verifier.Encode();
            var decoded = KrbVerifierMac.Decode(encoded);

            Assert.AreEqual(verifier.EncryptionType, decoded.EncryptionType);
            Assert.IsNotNull(decoded.Mac);
            Assert.AreEqual(verifier.Mac.Type, decoded.Mac.Type);
        }

        [TestMethod]
        public void KrbAdCammac_Create_NullElements_Throws()
        {
            var kdcKey = GenerateKey();

            Assert.ThrowsException<ArgumentNullException>(() =>
            {
                KrbAdCammac.Create(null, kdcKey);
            });
        }

        [TestMethod]
        public void KrbAdCammac_Create_NullKdcKey_Throws()
        {
            var elements = CreateTestElements();

            Assert.ThrowsException<ArgumentNullException>(() =>
            {
                KrbAdCammac.Create(elements, null);
            });
        }
    }
}
