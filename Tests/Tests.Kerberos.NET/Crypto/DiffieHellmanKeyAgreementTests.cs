using Kerberos.NET.Crypto;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

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
            Assert.IsTrue(dh.PublicKey.Length > 0);
        }

        [TestMethod]
        public void Oakley2_PublicKey()
        {
            var dh = new BCryptDiffieHellmanOakleyGroup2();

            Assert.IsNotNull(dh);

            Assert.IsNotNull(dh.PublicKey);
            Assert.IsTrue(dh.PublicKey.Length > 0);
        }

        [TestMethod]
        public void Oakley14_KeyAgreement()
        {
            using (var alice = new BCryptDiffieHellmanOakleyGroup14())
            using (var bob = new BCryptDiffieHellmanOakleyGroup14())
            {
                Assert.IsFalse(bob.PublicKey.Span.SequenceEqual(alice.PublicKey.Span));

                alice.ImportPartnerKey(bob.PublicKey.Span);
                bob.ImportPartnerKey(alice.PublicKey.Span);

                var aliceDerived = alice.GenerateAgreement();
                var bobDerived = bob.GenerateAgreement();

                Assert.IsTrue(aliceDerived.Span.SequenceEqual(bobDerived.Span));
            }
        }

        [TestMethod]
        public void Oakley2_KeyAgreement()
        {
            using (var alice = new BCryptDiffieHellmanOakleyGroup2())
            using (var bob = new BCryptDiffieHellmanOakleyGroup2())
            {
                Assert.IsFalse(bob.PublicKey.Span.SequenceEqual(alice.PublicKey.Span));

                alice.ImportPartnerKey(bob.PublicKey.Span);
                bob.ImportPartnerKey(alice.PublicKey.Span);

                var aliceDerived = alice.GenerateAgreement();
                var bobDerived = bob.GenerateAgreement();

                Assert.IsTrue(aliceDerived.Span.SequenceEqual(bobDerived.Span));
            }
        }
    }
}
