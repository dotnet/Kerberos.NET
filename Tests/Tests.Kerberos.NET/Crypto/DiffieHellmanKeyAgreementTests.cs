// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Linq;
using System.Numerics;
using Kerberos.NET.Crypto;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class DiffieHellmanKeyAgreementTests
    {
        [TestMethod]
        public void Oakley14_Ctor()
        {
            using (var dh = new BCryptDiffieHellmanOakleyGroup14())
            {
                Assert.IsNotNull(dh);
            }
        }

        [TestMethod]
        public void Oakley2_Ctor()
        {
            using (var dh = new BCryptDiffieHellmanOakleyGroup2())
            {
                Assert.IsNotNull(dh);
            }
        }

        [TestMethod]
        public void Oakley14_PublicKey()
        {
            using (var dh = new BCryptDiffieHellmanOakleyGroup14())
            {
                Assert.IsNotNull(dh);

                Assert.IsNotNull(dh.PublicKey);
                Assert.IsTrue(dh.PublicKey.KeyLength > 0);
            }
        }

        [TestMethod]
        public void Oakley2_PublicKey()
        {
            using (var dh = new BCryptDiffieHellmanOakleyGroup2())
            {
                Assert.IsNotNull(dh);

                Assert.IsNotNull(dh.PublicKey);
                Assert.IsTrue(dh.PublicKey.KeyLength > 0);
            }
        }

        [TestMethod]
        public void Oakley14_KeyAgreement()
        {
            using (var alice = new BCryptDiffieHellmanOakleyGroup14())
            using (var bob = new BCryptDiffieHellmanOakleyGroup14())
            {
                Assert.IsFalse(bob.PublicKey.PublicComponent.Span.SequenceEqual(alice.PublicKey.PublicComponent.Span));

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
                Assert.IsFalse(bob.PublicKey.PublicComponent.Span.SequenceEqual(alice.PublicKey.PublicComponent.Span));

                alice.ImportPartnerKey(GetRightPublicKey(alice.PublicKey, bob.PublicKey));
                bob.ImportPartnerKey(GetRightPublicKey(bob.PublicKey, alice.PublicKey));

                AssertKeysAgree(alice, bob);
            }
        }

        private static IExchangeKey GetRightPublicKey(IExchangeKey a, IExchangeKey b)
        {
            var left = a as DiffieHellmanKey;
            var right = b as DiffieHellmanKey;

            var pub = right.PublicComponent.ToArray();

            var key = new DiffieHellmanKey
            {
                KeyLength = left.Modulus.Length,
                Modulus = left.Modulus.ToArray(),
                Generator = left.Generator.ToArray(),
                PublicComponent = pub
            };

            return key;
        }

        [TestMethod]
        public void DHParametersAsBigInteger()
        {
            using (var eve = new BCryptDiffieHellmanOakleyGroup14())
            {
                var evePubKey = eve.PublicKey as DiffieHellmanKey;

                var eveMod = new BigInteger(evePubKey.Modulus.Span.ToArray());
                var eveGen = new BigInteger(evePubKey.Generator.Span.ToArray());
                var evePub = new BigInteger(evePubKey.PublicComponent.Span.ToArray());

                for (var i = 0; i < 100; i++)
                {
                    using (var alice = new BCryptDiffieHellmanOakleyGroup14())
                    using (var bob = new BCryptDiffieHellmanOakleyGroup14())
                    {
                        alice.ImportPartnerKey(bob.PublicKey);
                        bob.ImportPartnerKey(alice.PublicKey);

                        AssertKeysAgree(alice, bob);

                        var alicePubKey = alice.PublicKey as DiffieHellmanKey;
                        var bobPubKey = bob.PublicKey as DiffieHellmanKey;

                        var aliceMod = new BigInteger(alicePubKey.Modulus.Span.ToArray());
                        var bobMod = new BigInteger(bobPubKey.Modulus.Span.ToArray());

                        var alicePub = new BigInteger(alice.PublicKey.PublicComponent.Span.ToArray());
                        var bobPub = new BigInteger(bob.PublicKey.PublicComponent.Span.ToArray());

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
            IExchangeKey aliceKey = null;
            IExchangeKey bobKey = null;

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
                managedExport = alice.PrivateKey as DiffieHellmanKey;

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
                var managedExportPrivate = alice.PrivateKey as DiffieHellmanKey;
                var managedExportPublic = alice.PublicKey as DiffieHellmanKey;

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

        private static void AssertKeysMatch(IExchangeKey a, IExchangeKey b)
        {
            var alice = a as DiffieHellmanKey;
            var bob = b as DiffieHellmanKey;

            Assert.IsTrue(alice.Modulus.Span.SequenceEqual(bob.Modulus.Span));
            Assert.IsTrue(alice.Generator.Span.SequenceEqual(bob.Generator.Span));
            Assert.IsTrue(alice.Factor.Span.SequenceEqual(bob.Factor.Span));
            Assert.IsTrue(alice.PublicComponent.Span.SequenceEqual(bob.PublicComponent.Span));

            Assert.IsTrue(alice.PrivateComponent.Span.SequenceEqual(bob.PrivateComponent.Span));
        }

        private static ReadOnlyMemory<byte> Pad(ReadOnlyMemory<byte> data, int length)
        {
            var copy = new Memory<byte>(new byte[length]);

            data.CopyTo(copy.Slice(length - data.Length));

            return copy;
        }
    }
}