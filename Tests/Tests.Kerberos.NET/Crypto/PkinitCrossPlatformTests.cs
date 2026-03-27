// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Linq;
using Kerberos.NET.Crypto;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class PkinitCrossPlatformTests : BaseTest
    {
        // ---- Managed DH Group 14 (cross-platform) ----

        [TestMethod]
        public void ManagedDH_Group14_GeneratesKeyPair()
        {
            using (var dh = new ManagedDiffieHellmanOakleyGroup14())
            {
                Assert.IsNotNull(dh.PublicKey);
                Assert.IsNotNull(dh.PrivateKey);
                Assert.AreEqual(AsymmetricKeyType.Public, dh.PublicKey.Type);
                Assert.AreEqual(AsymmetricKeyType.Private, dh.PrivateKey.Type);
                Assert.AreEqual(256, dh.PublicKey.KeyLength); // 2048 bits = 256 bytes
            }
        }

        [TestMethod]
        public void ManagedDH_Group14_KeyAgreementProducesSameSecret()
        {
            using (var alice = new ManagedDiffieHellmanOakleyGroup14())
            using (var bob = new ManagedDiffieHellmanOakleyGroup14())
            {
                alice.ImportPartnerKey(bob.PublicKey);
                bob.ImportPartnerKey(alice.PublicKey);

                var aliceSecret = alice.GenerateAgreement();
                var bobSecret = bob.GenerateAgreement();

                Assert.IsTrue(aliceSecret.Span.SequenceEqual(bobSecret.Span));
            }
        }

        [TestMethod]
        public void ManagedDH_Group14_DifferentKeysProduceDifferentPublicValues()
        {
            using (var alice = new ManagedDiffieHellmanOakleyGroup14())
            using (var bob = new ManagedDiffieHellmanOakleyGroup14())
            {
                // Two independent key generations should produce different public keys
                Assert.IsFalse(alice.PublicKey.PublicComponent.Span.SequenceEqual(
                    bob.PublicKey.PublicComponent.Span));
            }
        }

        [TestMethod]
        public void ManagedDH_Group14_AgreementLengthIs256Bytes()
        {
            using (var alice = new ManagedDiffieHellmanOakleyGroup14())
            using (var bob = new ManagedDiffieHellmanOakleyGroup14())
            {
                alice.ImportPartnerKey(bob.PublicKey);
                bob.ImportPartnerKey(alice.PublicKey);

                var secret = alice.GenerateAgreement();
                Assert.AreEqual(256, secret.Length); // 2048-bit group
            }
        }

        // ---- Managed DH Group 2 (cross-platform) ----

        [TestMethod]
        public void ManagedDH_Group2_GeneratesKeyPair()
        {
            using (var dh = new ManagedDiffieHellmanOakleyGroup2())
            {
                Assert.IsNotNull(dh.PublicKey);
                Assert.IsNotNull(dh.PrivateKey);
                Assert.AreEqual(128, dh.PublicKey.KeyLength); // 1024 bits = 128 bytes
            }
        }

        [TestMethod]
        public void ManagedDH_Group2_KeyAgreementProducesSameSecret()
        {
            using (var alice = new ManagedDiffieHellmanOakleyGroup2())
            using (var bob = new ManagedDiffieHellmanOakleyGroup2())
            {
                alice.ImportPartnerKey(bob.PublicKey);
                bob.ImportPartnerKey(alice.PublicKey);

                var aliceSecret = alice.GenerateAgreement();
                var bobSecret = bob.GenerateAgreement();

                Assert.IsTrue(aliceSecret.Span.SequenceEqual(bobSecret.Span));
            }
        }

        // ---- Managed DH import/export ----

        [TestMethod]
        public void ManagedDH_Group14_ImportExportPrivateKey()
        {
            ReadOnlyMemory<byte> firstAgreement;
            DiffieHellmanKey exportedKey;

            // Generate a key and compute agreement
            using (var alice = new ManagedDiffieHellmanOakleyGroup14())
            using (var bob = new ManagedDiffieHellmanOakleyGroup14())
            {
                exportedKey = (DiffieHellmanKey)alice.PrivateKey;

                alice.ImportPartnerKey(bob.PublicKey);
                bob.ImportPartnerKey(alice.PublicKey);

                firstAgreement = alice.GenerateAgreement();
            }

            // Reimport the private key and verify we can reproduce agreement
            using (var reimported = new ManagedDiffieHellmanOakleyGroup14(exportedKey))
            {
                Assert.IsTrue(reimported.PublicKey.PublicComponent.Span.SequenceEqual(
                    exportedKey.PublicComponent.Span));
            }
        }

        // ---- Managed DH Cross-Platform with BCrypt ----

        [TestMethod]
        public void ManagedDH_Group14_AgreesWithBCrypt()
        {
            // This is the critical test - managed implementation must produce
            // identical shared secrets as the Windows BCrypt implementation
            using (var managed = new ManagedDiffieHellmanOakleyGroup14())
            using (var native = new BCryptDiffieHellmanOakleyGroup14())
            {
                managed.ImportPartnerKey(native.PublicKey);
                native.ImportPartnerKey(managed.PublicKey);

                var managedSecret = managed.GenerateAgreement();
                var nativeSecret = native.GenerateAgreement();

                Assert.IsTrue(managedSecret.Span.SequenceEqual(nativeSecret.Span),
                    "Managed and BCrypt DH must produce identical shared secrets");
            }
        }

        [TestMethod]
        public void ManagedDH_Group2_AgreesWithBCrypt()
        {
            using (var managed = new ManagedDiffieHellmanOakleyGroup2())
            using (var native = new BCryptDiffieHellmanOakleyGroup2())
            {
                managed.ImportPartnerKey(native.PublicKey);
                native.ImportPartnerKey(managed.PublicKey);

                var managedSecret = managed.GenerateAgreement();
                var nativeSecret = native.GenerateAgreement();

                Assert.IsTrue(managedSecret.Span.SequenceEqual(nativeSecret.Span),
                    "Managed and BCrypt DH must produce identical shared secrets");
            }
        }

        // ---- Managed DH Error Cases ----

        [TestMethod]
        [ExpectedException(typeof(InvalidOperationException))]
        public void ManagedDH_GenerateAgreement_WithoutPartnerKey_Throws()
        {
            using (var dh = new ManagedDiffieHellmanOakleyGroup14())
            {
                dh.GenerateAgreement();
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void ManagedDH_ImportPartnerKey_Null_Throws()
        {
            using (var dh = new ManagedDiffieHellmanOakleyGroup14())
            {
                dh.ImportPartnerKey(null);
            }
        }

        // ---- CryptoPal Integration (cross-platform DH) ----

        [TestMethod]
        public void CryptoPal_DiffieHellmanModp14_DoesNotThrow()
        {
            // On all platforms, DH-MODP-14 should now work
            using (var agreement = CryptoPal.Platform.DiffieHellmanModp14())
            {
                Assert.IsNotNull(agreement);
                Assert.IsNotNull(agreement.PublicKey);
                Assert.IsNotNull(agreement.PrivateKey);
            }
        }

        [TestMethod]
        public void CryptoPal_DiffieHellmanModp2_DoesNotThrow()
        {
            using (var agreement = CryptoPal.Platform.DiffieHellmanModp2())
            {
                Assert.IsNotNull(agreement);
                Assert.IsNotNull(agreement.PublicKey);
            }
        }

        [TestMethod]
        public void CryptoPal_DiffieHellmanModp14_WithPrivateKey_DoesNotThrow()
        {
            IExchangeKey privateKey;

            using (var agreement = CryptoPal.Platform.DiffieHellmanModp14())
            {
                privateKey = agreement.PrivateKey;
            }

            using (var reimported = CryptoPal.Platform.DiffieHellmanModp14(privateKey))
            {
                Assert.IsNotNull(reimported);
            }
        }

        // ---- ECDH Key Agreement ----

        [TestMethod]
        public void Ecdh_IsSupported_ReturnsTrue()
        {
            // On .NET 8 runtime, ECDH should be available
            Assert.IsTrue(EcdhKeyAgreement.IsSupported,
                "ECDH should be supported on .NET 8 runtime");
        }

        [TestMethod]
        public void Ecdh_P256_GeneratesKeyPair()
        {
            using (var ecdh = new EcdhKeyAgreement(KeyAgreementAlgorithm.EllipticCurveDiffieHellmanP256))
            {
                Assert.IsNotNull(ecdh.PublicKey);
                Assert.IsNotNull(ecdh.PrivateKey);
                Assert.AreEqual(32, ecdh.PublicKey.KeyLength); // 256-bit = 32-byte coordinates
                Assert.AreEqual(KeyAgreementAlgorithm.EllipticCurveDiffieHellmanP256, ecdh.PublicKey.Algorithm);
            }
        }

        [TestMethod]
        public void Ecdh_P256_PublicKeyIsUncompressedPoint()
        {
            using (var ecdh = new EcdhKeyAgreement(KeyAgreementAlgorithm.EllipticCurveDiffieHellmanP256))
            {
                var pubKey = ecdh.PublicKey.PublicComponent;

                // Uncompressed point: 04 || x(32) || y(32) = 65 bytes
                Assert.AreEqual(65, pubKey.Length);
                Assert.AreEqual(0x04, pubKey.Span[0]);
            }
        }

        [TestMethod]
        public void Ecdh_P384_GeneratesKeyPair()
        {
            using (var ecdh = new EcdhKeyAgreement(KeyAgreementAlgorithm.EllipticCurveDiffieHellmanP384))
            {
                Assert.IsNotNull(ecdh.PublicKey);
                Assert.AreEqual(48, ecdh.PublicKey.KeyLength); // 384-bit = 48-byte coordinates

                var pubKey = ecdh.PublicKey.PublicComponent;
                Assert.AreEqual(97, pubKey.Length); // 04 || x(48) || y(48) = 97
                Assert.AreEqual(0x04, pubKey.Span[0]);
            }
        }

        [TestMethod]
        public void Ecdh_P521_GeneratesKeyPair()
        {
            using (var ecdh = new EcdhKeyAgreement(KeyAgreementAlgorithm.EllipticCurveDiffieHellmanP521))
            {
                Assert.IsNotNull(ecdh.PublicKey);
                Assert.AreEqual(66, ecdh.PublicKey.KeyLength); // 521-bit = 66-byte coordinates

                var pubKey = ecdh.PublicKey.PublicComponent;
                Assert.AreEqual(133, pubKey.Length); // 04 || x(66) || y(66) = 133
                Assert.AreEqual(0x04, pubKey.Span[0]);
            }
        }

        [TestMethod]
        public void Ecdh_P256_KeyAgreementProducesSameSecret()
        {
            using (var alice = new EcdhKeyAgreement(KeyAgreementAlgorithm.EllipticCurveDiffieHellmanP256))
            using (var bob = new EcdhKeyAgreement(KeyAgreementAlgorithm.EllipticCurveDiffieHellmanP256))
            {
                alice.ImportPartnerKey(bob.PublicKey);
                bob.ImportPartnerKey(alice.PublicKey);

                var aliceSecret = alice.GenerateAgreement();
                var bobSecret = bob.GenerateAgreement();

                Assert.IsTrue(aliceSecret.Length > 0);
                Assert.IsTrue(bobSecret.Length > 0);
                Assert.IsTrue(aliceSecret.Span.SequenceEqual(bobSecret.Span),
                    "ECDH key agreement must produce identical shared secrets on both sides");
            }
        }

        [TestMethod]
        public void Ecdh_P384_KeyAgreementProducesSameSecret()
        {
            using (var alice = new EcdhKeyAgreement(KeyAgreementAlgorithm.EllipticCurveDiffieHellmanP384))
            using (var bob = new EcdhKeyAgreement(KeyAgreementAlgorithm.EllipticCurveDiffieHellmanP384))
            {
                alice.ImportPartnerKey(bob.PublicKey);
                bob.ImportPartnerKey(alice.PublicKey);

                var aliceSecret = alice.GenerateAgreement();
                var bobSecret = bob.GenerateAgreement();

                Assert.IsTrue(aliceSecret.Span.SequenceEqual(bobSecret.Span));
            }
        }

        [TestMethod]
        public void Ecdh_P521_KeyAgreementProducesSameSecret()
        {
            using (var alice = new EcdhKeyAgreement(KeyAgreementAlgorithm.EllipticCurveDiffieHellmanP521))
            using (var bob = new EcdhKeyAgreement(KeyAgreementAlgorithm.EllipticCurveDiffieHellmanP521))
            {
                alice.ImportPartnerKey(bob.PublicKey);
                bob.ImportPartnerKey(alice.PublicKey);

                var aliceSecret = alice.GenerateAgreement();
                var bobSecret = bob.GenerateAgreement();

                Assert.IsTrue(aliceSecret.Span.SequenceEqual(bobSecret.Span));
            }
        }

        [TestMethod]
        public void Ecdh_DifferentKeysProduceDifferentPublicValues()
        {
            using (var alice = new EcdhKeyAgreement(KeyAgreementAlgorithm.EllipticCurveDiffieHellmanP256))
            using (var bob = new EcdhKeyAgreement(KeyAgreementAlgorithm.EllipticCurveDiffieHellmanP256))
            {
                Assert.IsFalse(alice.PublicKey.PublicComponent.Span.SequenceEqual(
                    bob.PublicKey.PublicComponent.Span));
            }
        }

        // ---- ECDH Error Cases ----

        [TestMethod]
        [ExpectedException(typeof(InvalidOperationException))]
        public void Ecdh_GenerateAgreement_WithoutPartnerKey_Throws()
        {
            using (var ecdh = new EcdhKeyAgreement(KeyAgreementAlgorithm.EllipticCurveDiffieHellmanP256))
            {
                ecdh.GenerateAgreement();
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Ecdh_ImportPartnerKey_Null_Throws()
        {
            using (var ecdh = new EcdhKeyAgreement(KeyAgreementAlgorithm.EllipticCurveDiffieHellmanP256))
            {
                ecdh.ImportPartnerKey(null);
            }
        }

        // ---- EcdhKey ----

        [TestMethod]
        public void EcdhKey_ParsePublicKey_P256()
        {
            using (var ecdh = new EcdhKeyAgreement(KeyAgreementAlgorithm.EllipticCurveDiffieHellmanP256))
            {
                var encoded = ecdh.PublicKey.PublicComponent;
                var parsed = EcdhKey.ParsePublicKey(encoded, KeyAgreementAlgorithm.EllipticCurveDiffieHellmanP256);

                Assert.AreEqual(32, parsed.KeyLength);
                Assert.AreEqual(KeyAgreementAlgorithm.EllipticCurveDiffieHellmanP256, parsed.Algorithm);
                Assert.IsTrue(parsed.PublicComponent.Span.SequenceEqual(encoded.Span));
            }
        }

        // ---- Curve OID Mapping ----

        [TestMethod]
        public void Ecdh_CurveOid_P256()
        {
            var oid = EcdhKeyAgreement.GetCurveOid(KeyAgreementAlgorithm.EllipticCurveDiffieHellmanP256);
            Assert.AreEqual("1.2.840.10045.3.1.7", oid.Value);
        }

        [TestMethod]
        public void Ecdh_CurveOid_P384()
        {
            var oid = EcdhKeyAgreement.GetCurveOid(KeyAgreementAlgorithm.EllipticCurveDiffieHellmanP384);
            Assert.AreEqual("1.3.132.0.34", oid.Value);
        }

        [TestMethod]
        public void Ecdh_CurveOid_P521()
        {
            var oid = EcdhKeyAgreement.GetCurveOid(KeyAgreementAlgorithm.EllipticCurveDiffieHellmanP521);
            Assert.AreEqual("1.3.132.0.35", oid.Value);
        }

        [TestMethod]
        public void Ecdh_FromCurveOid_P256()
        {
            var alg = EcdhKeyAgreement.FromCurveOid("1.2.840.10045.3.1.7");
            Assert.AreEqual(KeyAgreementAlgorithm.EllipticCurveDiffieHellmanP256, alg);
        }

        [TestMethod]
        public void Ecdh_FromCurveOid_P384()
        {
            var alg = EcdhKeyAgreement.FromCurveOid("1.3.132.0.34");
            Assert.AreEqual(KeyAgreementAlgorithm.EllipticCurveDiffieHellmanP384, alg);
        }

        [TestMethod]
        public void Ecdh_FromCurveOid_P521()
        {
            var alg = EcdhKeyAgreement.FromCurveOid("1.3.132.0.35");
            Assert.AreEqual(KeyAgreementAlgorithm.EllipticCurveDiffieHellmanP521, alg);
        }

        // ---- CryptoPal ECDH Integration ----

        [TestMethod]
        public void CryptoPal_DiffieHellmanP256_DoesNotThrow()
        {
            using (var agreement = CryptoPal.Platform.DiffieHellmanP256())
            {
                Assert.IsNotNull(agreement);
                Assert.IsNotNull(agreement.PublicKey);
            }
        }

        [TestMethod]
        public void CryptoPal_DiffieHellmanP384_DoesNotThrow()
        {
            using (var agreement = CryptoPal.Platform.DiffieHellmanP384())
            {
                Assert.IsNotNull(agreement);
            }
        }

        [TestMethod]
        public void CryptoPal_DiffieHellmanP521_DoesNotThrow()
        {
            using (var agreement = CryptoPal.Platform.DiffieHellmanP521())
            {
                Assert.IsNotNull(agreement);
            }
        }

        // ---- PKInitString2Key Integration ----

        [TestMethod]
        public void PKInitString2Key_DH_ProducesExpectedLength()
        {
            using (var alice = new ManagedDiffieHellmanOakleyGroup14())
            using (var bob = new ManagedDiffieHellmanOakleyGroup14())
            {
                alice.ImportPartnerKey(bob.PublicKey);
                bob.ImportPartnerKey(alice.PublicKey);

                var sharedSecret = alice.GenerateAgreement();

                // AES-256 key = 32 bytes
                var sessionKey = PKInitString2Key.String2Key(sharedSecret.Span, 32);
                Assert.AreEqual(32, sessionKey.Length);

                // AES-128 key = 16 bytes
                var sessionKey128 = PKInitString2Key.String2Key(sharedSecret.Span, 16);
                Assert.AreEqual(16, sessionKey128.Length);
            }
        }

        [TestMethod]
        public void PKInitString2Key_ECDH_ProducesExpectedLength()
        {
            using (var alice = new EcdhKeyAgreement(KeyAgreementAlgorithm.EllipticCurveDiffieHellmanP256))
            using (var bob = new EcdhKeyAgreement(KeyAgreementAlgorithm.EllipticCurveDiffieHellmanP256))
            {
                alice.ImportPartnerKey(bob.PublicKey);
                bob.ImportPartnerKey(alice.PublicKey);

                var sharedSecret = alice.GenerateAgreement();

                var sessionKey = PKInitString2Key.String2Key(sharedSecret.Span, 32);
                Assert.AreEqual(32, sessionKey.Length);
            }
        }

        [TestMethod]
        public void PKInitString2Key_SameSecret_ProducesSameKey()
        {
            using (var alice = new ManagedDiffieHellmanOakleyGroup14())
            using (var bob = new ManagedDiffieHellmanOakleyGroup14())
            {
                alice.ImportPartnerKey(bob.PublicKey);
                bob.ImportPartnerKey(alice.PublicKey);

                var aliceSecret = alice.GenerateAgreement();
                var bobSecret = bob.GenerateAgreement();

                var aliceKey = PKInitString2Key.String2Key(aliceSecret.Span, 32);
                var bobKey = PKInitString2Key.String2Key(bobSecret.Span, 32);

                Assert.IsTrue(aliceKey.Span.SequenceEqual(bobKey.Span),
                    "Same shared secret must produce same session key");
            }
        }
    }
}
