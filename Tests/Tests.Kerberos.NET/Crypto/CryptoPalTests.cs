using Kerberos.NET.Crypto;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Runtime.InteropServices;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class CryptoPalTests
    {
        [TestMethod]
        public void SupportsWindowsPal()
        {
            var pal = CryptoPal.Platform;

            Assert.IsNotNull(pal);

            Assert.AreEqual(OSPlatform.Windows, pal.OSPlatform);
        }

        [TestMethod]
        public void PalSupportsMd4()
        {
            var md4 = CryptoPal.Platform.Md4();

            Assert.IsNotNull(md4);
        }

        [TestMethod]
        public void PalSupportsMd5()
        {
            var md5 = CryptoPal.Platform.Md5();

            Assert.IsNotNull(md5);
        }

        [TestMethod]
        public void PalSupportsHmacMd5()
        {
            var hmac = CryptoPal.Platform.HmacMd5();

            Assert.IsNotNull(hmac);
        }

        [TestMethod]
        public void PalSupportsHmacSha1()
        {
            var hmac = CryptoPal.Platform.HmacSha1();

            Assert.IsNotNull(hmac);
        }

        [TestMethod]
        public void PalSupportsSha256()
        {
            var sha = CryptoPal.Platform.Sha256();

            Assert.IsNotNull(sha);
        }

        [TestMethod]
        public void PalSupportsAes()
        {
            var aes = CryptoPal.Platform.Aes();

            Assert.IsNotNull(aes);
        }

        [TestMethod]
        public void PalSupportsPbkdf2()
        {
            var pbkdf2 = CryptoPal.Platform.Rfc2898DeriveBytes();

            Assert.IsNotNull(pbkdf2);
        }

        [TestMethod]
        public void PalSupportsDHModp14()
        {
            var dh = CryptoPal.Platform.DiffieHellmanModp14();

            Assert.IsNotNull(dh);
        }

        [TestMethod]
        public void PalSupportsDHModp14_WithImport()
        {
            var dh = CryptoPal.Platform.DiffieHellmanModp14();

            Assert.IsNotNull(dh);

            var pk = dh.PrivateKey;

            var dh2 = CryptoPal.Platform.DiffieHellmanModp14(pk);

            Assert.IsNotNull(dh2);
        }

        [TestMethod]
        public void PalSupportsInjected()
        {
            CryptoPal.RegisterPal(() => new FakeCryptoPal());

            Assert.IsInstanceOfType(CryptoPal.Platform, typeof(FakeCryptoPal));
        }

        [TestMethod, ExpectedException(typeof(InvalidOperationException))]
        public void PalBlocksInjectedNull()
        {
            CryptoPal.RegisterPal(null);
        }

        private class FakeCryptoPal : CryptoPal
        {
            public override OSPlatform OSPlatform => throw new System.NotImplementedException();

            public override ISymmetricAlgorithm Aes()
            {
                throw new System.NotImplementedException();
            }

            public override IKeyAgreement DiffieHellmanModp14()
            {
                throw new System.NotImplementedException();
            }

            public override IKeyAgreement DiffieHellmanModp14(IExchangeKey privateKey)
            {
                throw new System.NotImplementedException();
            }

            public override IKeyAgreement DiffieHellmanModp2()
            {
                throw new System.NotImplementedException();
            }

            public override IKeyAgreement DiffieHellmanModp2(IExchangeKey privateKey)
            {
                throw new System.NotImplementedException();
            }

            public override IKeyAgreement DiffieHellmanP256()
            {
                throw new System.NotImplementedException();
            }

            public override IHmacAlgorithm HmacMd5()
            {
                throw new System.NotImplementedException();
            }

            public override IHmacAlgorithm HmacSha1()
            {
                throw new System.NotImplementedException();
            }

            public override IHashAlgorithm Md4()
            {
                throw new System.NotImplementedException();
            }

            public override IHashAlgorithm Md5()
            {
                throw new System.NotImplementedException();
            }

            public override IKeyDerivationAlgorithm Rfc2898DeriveBytes()
            {
                throw new System.NotImplementedException();
            }

            public override IHashAlgorithm Sha1()
            {
                throw new System.NotImplementedException();
            }

            public override IHashAlgorithm Sha256()
            {
                throw new System.NotImplementedException();
            }
        }
    }
}
