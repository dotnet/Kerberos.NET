// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Linq;
using System.Security.Cryptography;
using Kerberos.NET.Configuration;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Server;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class SpakeTests : BaseTest
    {
        [TestMethod]
        public void SpakeExchange_GetKeySize_AllGroups()
        {
            Assert.AreEqual(32, SpakeExchange.GetKeySize(SpakePreAuthGroupType.Edwards25519));
            Assert.AreEqual(32, SpakeExchange.GetKeySize(SpakePreAuthGroupType.P_256));
            Assert.AreEqual(48, SpakeExchange.GetKeySize(SpakePreAuthGroupType.P_384));
            Assert.AreEqual(66, SpakeExchange.GetKeySize(SpakePreAuthGroupType.P_521));
        }

        [TestMethod]
        public void SpakeExchange_GetHashAlgorithm_AllGroups()
        {
            Assert.AreEqual(HashAlgorithmName.SHA256, SpakeExchange.GetHashAlgorithm(SpakePreAuthGroupType.Edwards25519));
            Assert.AreEqual(HashAlgorithmName.SHA256, SpakeExchange.GetHashAlgorithm(SpakePreAuthGroupType.P_256));
            Assert.AreEqual(HashAlgorithmName.SHA384, SpakeExchange.GetHashAlgorithm(SpakePreAuthGroupType.P_384));
            Assert.AreEqual(HashAlgorithmName.SHA512, SpakeExchange.GetHashAlgorithm(SpakePreAuthGroupType.P_521));
        }

        [TestMethod]
        public void SpakeExchange_GenerateScalar_CorrectLength()
        {
            var groups = new[]
            {
                SpakePreAuthGroupType.Edwards25519,
                SpakePreAuthGroupType.P_256,
                SpakePreAuthGroupType.P_384,
                SpakePreAuthGroupType.P_521
            };

            foreach (var group in groups)
            {
                var scalar = SpakeExchange.GenerateScalar(group);
                var expectedSize = SpakeExchange.GetKeySize(group);

                Assert.AreEqual(expectedSize, scalar.Length, $"Scalar length mismatch for group {group}");
            }
        }

        [TestMethod]
        public void SpakeExchange_GenerateScalar_IsRandom()
        {
            var groups = new[]
            {
                SpakePreAuthGroupType.Edwards25519,
                SpakePreAuthGroupType.P_256,
                SpakePreAuthGroupType.P_384,
                SpakePreAuthGroupType.P_521
            };

            foreach (var group in groups)
            {
                var scalar1 = SpakeExchange.GenerateScalar(group);
                var scalar2 = SpakeExchange.GenerateScalar(group);

                Assert.IsFalse(
                    scalar1.SequenceEqual(scalar2),
                    $"Two generated scalars should differ for group {group}");
            }
        }

        [TestMethod]
        public void SpakeExchange_DeriveKey_Deterministic()
        {
            var group = SpakePreAuthGroupType.P_256;
            var sharedSecret = new byte[32];
            var transcript = new byte[64];

            Array.Fill<byte>(sharedSecret, 0xAA);
            Array.Fill<byte>(transcript, 0xBB);

            var key1 = SpakeExchange.DeriveKey(group, sharedSecret, transcript);
            var key2 = SpakeExchange.DeriveKey(group, sharedSecret, transcript);

            Assert.IsNotNull(key1);
            Assert.IsTrue(key1.Length > 0);
            Assert.IsTrue(key1.SequenceEqual(key2), "Same inputs must produce the same derived key");
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void SpakeExchange_DeriveKey_NullSharedSecret_Throws()
        {
            SpakeExchange.DeriveKey(SpakePreAuthGroupType.P_256, null, new byte[64]);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void SpakeExchange_DeriveKey_NullTranscript_Throws()
        {
            SpakeExchange.DeriveKey(SpakePreAuthGroupType.P_256, new byte[32], null);
        }

        [TestMethod]
        public void SpakeExchange_DeriveKey_DifferentInputs_DifferentOutput()
        {
            var group = SpakePreAuthGroupType.P_256;
            var transcript = new byte[64];
            Array.Fill<byte>(transcript, 0xCC);

            var secret1 = new byte[32];
            var secret2 = new byte[32];
            Array.Fill<byte>(secret1, 0x11);
            Array.Fill<byte>(secret2, 0x22);

            var key1 = SpakeExchange.DeriveKey(group, secret1, transcript);
            var key2 = SpakeExchange.DeriveKey(group, secret2, transcript);

            Assert.IsFalse(
                key1.SequenceEqual(key2),
                "Different shared secrets must produce different derived keys");
        }

        [TestMethod]
        public void SpakeState_DefaultValues()
        {
            var state = new SpakeState();

            Assert.AreEqual(default(SpakePreAuthGroupType), state.SelectedGroup);
            Assert.IsFalse(state.ChallengeSent);
            Assert.IsNull(state.ServerPrivateKey);
            Assert.IsNull(state.SharedSecret);
        }

        [TestMethod]
        public void PaDataSpakeHandler_PreValidate_SkipsWhenNotSupported()
        {
            var realmService = new FakeRealmService("CORP.TEST.COM");
            var handler = new PaDataSpakeHandler(realmService);

            var principal = new FakeKerberosPrincipal("user@CORP.TEST.COM")
            {
                SupportedPreAuthenticationTypes = new[] { PaDataType.PA_ENC_TIMESTAMP }
            };

            var preauth = new PreAuthenticationContext
            {
                Principal = principal
            };

            handler.PreValidate(preauth);

            Assert.IsFalse(
                preauth.PreAuthenticationState.ContainsKey(PaDataType.PA_SPAKE),
                "SPAKE state should not be created when principal does not support PA_SPAKE");
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void PaDataSpakeHandler_PreValidate_NullPreauth_Throws()
        {
            var realmService = new FakeRealmService("CORP.TEST.COM");
            var handler = new PaDataSpakeHandler(realmService);

            handler.PreValidate(null);
        }

        [TestMethod]
        public void PaDataSpakeHandler_Validate_NoSpakeData_ReturnsChallenge()
        {
            var realmService = new FakeRealmService("CORP.TEST.COM");
            var handler = new PaDataSpakeHandler(realmService);

            var principal = new FakeKerberosPrincipal("user@CORP.TEST.COM")
            {
                SupportedPreAuthenticationTypes = new[]
                {
                    PaDataType.PA_ENC_TIMESTAMP,
                    PaDataType.PA_SPAKE
                }
            };

            var preauth = new PreAuthenticationContext
            {
                Principal = principal
            };

            // Pre-validate to initialize SPAKE state
            handler.PreValidate(preauth);

            // Create an AS-REQ without any PA_SPAKE data
            var asReq = new KrbAsReq
            {
                Body = new KrbKdcReqBody
                {
                    CName = new KrbPrincipalName
                    {
                        Type = PrincipalNameType.NT_PRINCIPAL,
                        Name = new[] { "user@CORP.TEST.COM" }
                    },
                    Realm = "CORP.TEST.COM",
                    EType = new[] { EncryptionType.AES256_CTS_HMAC_SHA1_96 }
                },
                PaData = Array.Empty<KrbPaData>()
            };

            var result = handler.Validate(asReq, preauth);

            Assert.IsNotNull(result, "First round should return a challenge PA-Data");
            Assert.AreEqual(PaDataType.PA_SPAKE, result.Type, "Challenge PA-Data should have PA_SPAKE type");
            Assert.IsTrue(result.Value.Length > 0, "Challenge PA-Data should contain data");
        }
    }
}
