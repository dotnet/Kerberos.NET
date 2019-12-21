using Kerberos.NET.Crypto;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Linq;
using System.Numerics;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class DiffieHellmanKeyAgreementTests
    {
        [TestMethod]
        public void Oakley14_Ctor()
        {
            var dh = new BCryptDiffieHellmanOakleyGroup14();

            Assert.IsNotNull(dh);
        }

        [TestMethod]
        public void Oakley2_Ctor()
        {
            var dh = new BCryptDiffieHellmanOakleyGroup2();

            Assert.IsNotNull(dh);
        }

        [TestMethod]
        public void Oakley14_PublicKey()
        {
            var dh = new BCryptDiffieHellmanOakleyGroup14();

            Assert.IsNotNull(dh);

            Assert.IsNotNull(dh.PublicKey);
            Assert.IsTrue(dh.PublicKey.KeyLength > 0);
        }

        [TestMethod]
        public void Oakley2_PublicKey()
        {
            var dh = new BCryptDiffieHellmanOakleyGroup2();

            Assert.IsNotNull(dh);

            Assert.IsNotNull(dh.PublicKey);
            Assert.IsTrue(dh.PublicKey.KeyLength > 0);
        }

        [TestMethod]
        public void Oakley14_KeyAgreement()
        {
            using (var alice = new BCryptDiffieHellmanOakleyGroup14())
            using (var bob = new BCryptDiffieHellmanOakleyGroup14())
            {
                Assert.IsFalse(bob.PublicKey.Public.Span.SequenceEqual(alice.PublicKey.Public.Span));

                alice.ImportPartnerKey(GetRightPublicKey(alice.PublicKey, bob.PublicKey));
                bob.ImportPartnerKey(GetRightPublicKey(bob.PublicKey, alice.PublicKey));

                AssertKeysAgree(alice, bob);
            }
        }

        private static void AssertKeysAgree(IKeyAgreement alice, IKeyAgreement bob)
        {
            var aliceDerived = alice.GenerateAgreement();
            var bobDerived = bob.GenerateAgreement();

            var match = aliceDerived.Span.SequenceEqual(bobDerived.Span);

            if (!match)
            {
                Hex.Debug(aliceDerived.ToArray());
                Hex.Debug(bobDerived.ToArray());
            }

            Assert.IsTrue(match);

            var empty = new byte[aliceDerived.Length];

            Assert.IsFalse(aliceDerived.Span.SequenceEqual(empty));
        }

        [TestMethod]
        public void Oakley2_KeyAgreement()
        {
            using (var alice = new BCryptDiffieHellmanOakleyGroup2())
            using (var bob = new BCryptDiffieHellmanOakleyGroup2())
            {
                Assert.IsFalse(bob.PublicKey.Public.Span.SequenceEqual(alice.PublicKey.Public.Span));

                alice.ImportPartnerKey(GetRightPublicKey(alice.PublicKey, bob.PublicKey));
                bob.ImportPartnerKey(GetRightPublicKey(bob.PublicKey, alice.PublicKey));

                AssertKeysAgree(alice, bob);
            }
        }

        private static DiffieHellmanKey GetRightPublicKey(DiffieHellmanKey left, DiffieHellmanKey right)
        {
            var pub = right.Public.ToArray();

            var key = new DiffieHellmanKey
            {
                KeyLength = left.Modulus.Length,
                Modulus = left.Modulus.ToArray(),
                Generator = left.Generator.ToArray(),
                Public = pub
            };

            return key;
        }

        [TestMethod]
        public void DHParametersAsBigInteger()
        {
            using (var eve = new BCryptDiffieHellmanOakleyGroup14())
            {
                var eveMod = new BigInteger(eve.PublicKey.Modulus.Span, isUnsigned: true);
                var eveGen = new BigInteger(eve.PublicKey.Generator.Span, isUnsigned: true);
                var evePub = new BigInteger(eve.PublicKey.Public.Span, isUnsigned: true);

                for (var i = 0; i < 100; i++)
                {
                    using (var alice = new BCryptDiffieHellmanOakleyGroup14())
                    using (var bob = new BCryptDiffieHellmanOakleyGroup14())
                    {
                        alice.ImportPartnerKey(bob.PublicKey);
                        bob.ImportPartnerKey(alice.PublicKey);

                        AssertKeysAgree(alice, bob);

                        var aliceMod = new BigInteger(alice.PublicKey.Modulus.Span, isUnsigned: true);
                        var bobMod = new BigInteger(bob.PublicKey.Modulus.Span, isUnsigned: true);

                        var alicePub = new BigInteger(alice.PublicKey.Public.Span, isUnsigned: true);
                        var bobPub = new BigInteger(bob.PublicKey.Public.Span, isUnsigned: true);

                        Assert.AreEqual(aliceMod, bobMod);
                        Assert.AreNotEqual(alicePub, bobPub);

                        Assert.AreEqual(aliceMod, eveMod);
                    }
                }
            }
        }

        [TestMethod]
        public void ImportPrivateKey()
        {
            DiffieHellmanKey aliceKey = null;
            DiffieHellmanKey bobKey = null;

            byte[] firstPassDerivedKey = null;

            using (var alice = new BCryptDiffieHellmanOakleyGroup14())
            using (var bob = new BCryptDiffieHellmanOakleyGroup14())
            {
                aliceKey = alice.PrivateKey;
                bobKey = bob.PrivateKey;

                alice.ImportPartnerKey(bob.PublicKey);
                bob.ImportPartnerKey(alice.PublicKey);

                AssertKeysAgree(alice, bob);

                firstPassDerivedKey = alice.GenerateAgreement().ToArray();
            }

            using (var alice = BCryptDiffieHellman.Import(aliceKey))
            using (var bob = BCryptDiffieHellman.Import(bobKey))
            {
                alice.ImportPartnerKey(bob.PublicKey);
                bob.ImportPartnerKey(alice.PublicKey);

                var aliceDerived = alice.GenerateAgreement();

                AssertKeysAgree(alice, bob);

                Assert.IsTrue(aliceDerived.Span.SequenceEqual(firstPassDerivedKey));
            }
        }

        [TestMethod]
        public void ManagedAgreesWithManagedGroup14()
        {
            using (var alice = new ManagedDiffieHellmanOakley14())
            using (var bob = new ManagedDiffieHellmanOakley14())
            {
                alice.ImportPartnerKey(bob.PublicKey);
                bob.ImportPartnerKey(alice.PublicKey);

                AssertKeysAgree(alice, bob);
            }
        }

        [TestMethod]
        public void ManagedAgreesWithNativeGroup14()
        {
            using (var alice = new BCryptDiffieHellmanOakleyGroup14())
            using (var bob = new ManagedDiffieHellmanOakley14())
            {
                alice.ImportPartnerKey(bob.PublicKey);
                bob.ImportPartnerKey(alice.PublicKey);

                AssertKeysAgree(alice, bob);
            }
        }

        [TestMethod]
        public void ManagedAgreesWithManagedGroup2()
        {
            using (var alice = new ManagedDiffieHellmanOakley2())
            using (var bob = new ManagedDiffieHellmanOakley2())
            {
                alice.ImportPartnerKey(bob.PublicKey);
                bob.ImportPartnerKey(alice.PublicKey);

                AssertKeysAgree(alice, bob);
            }
        }

        [TestMethod]
        public void ManagedAgreesWithNativeGroup2()
        {
            using (var alice = new BCryptDiffieHellmanOakleyGroup2())
            using (var bob = new ManagedDiffieHellmanOakley2())
            {
                alice.ImportPartnerKey(bob.PublicKey);
                bob.ImportPartnerKey(alice.PublicKey);

                AssertKeysAgree(alice, bob);
            }
        }

        [TestMethod]
        public void ManagedExportAgreeswithNativeImportGroup2()
        {
            DiffieHellmanKey managedExport;

            using (var alice = new ManagedDiffieHellmanOakley2())
            using (var bob = new ManagedDiffieHellmanOakley2())
            {
                managedExport = alice.PrivateKey;

                alice.ImportPartnerKey(bob.PublicKey);
                bob.ImportPartnerKey(alice.PublicKey);

                AssertKeysAgree(alice, bob);
            }

            managedExport.Generator = Pad(managedExport.Generator, managedExport.KeyLength);

            using (var alice = BCryptDiffieHellman.Import(managedExport))
            using (var bob = new BCryptDiffieHellmanOakleyGroup2())
            {
                alice.ImportPartnerKey(bob.PublicKey);
                bob.ImportPartnerKey(alice.PublicKey);

                AssertKeysAgree(alice, bob);
            }
        }

        [TestMethod]
        public void ManagedExportMatchesNativeImport()
        {
            using (var alice = new ManagedDiffieHellmanOakley2())
            {
                var managedExportPrivate = alice.PrivateKey;
                var managedExportPublic = alice.PublicKey;

                managedExportPrivate.Generator = Pad(managedExportPrivate.Generator, managedExportPrivate.KeyLength);
                managedExportPublic.Generator = Pad(managedExportPublic.Generator, managedExportPublic.KeyLength);

                using (var bob = BCryptDiffieHellman.Import(managedExportPrivate))
                {
                    AssertKeysMatch(alice.PrivateKey, bob.PrivateKey);
                    AssertKeysMatch(alice.PublicKey, bob.PublicKey);

                    alice.ImportPartnerKey(bob.PublicKey);
                    bob.ImportPartnerKey(alice.PublicKey);

                    AssertKeysAgree(alice, bob);
                }
            }
        }

        private void AssertKeysMatch(DiffieHellmanKey alice, DiffieHellmanKey bob)
        {
            Assert.IsTrue(alice.Modulus.Span.SequenceEqual(bob.Modulus.Span));
            Assert.IsTrue(alice.Generator.Span.SequenceEqual(bob.Generator.Span));
            Assert.IsTrue(alice.Factor.Span.SequenceEqual(bob.Factor.Span));
            Assert.IsTrue(alice.Public.Span.SequenceEqual(bob.Public.Span));
            
            Assert.IsTrue(alice.Private.Span.SequenceEqual(bob.Private.Span));
        }

        private ReadOnlyMemory<byte> Pad(ReadOnlyMemory<byte> data, int length)
        {
            var copy = new Memory<byte>(new byte[length]);

            data.CopyTo(copy.Slice(length - data.Length));

            return copy;
        }
    }
}
