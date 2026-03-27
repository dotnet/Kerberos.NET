// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using Kerberos.NET.Crypto;
using Microsoft.VisualStudio.TestTools.UnitTesting;

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
        }

#if WEAKCRYPTO
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
            var hmac = CryptoPal.Platform.HmacMd5(default);

            Assert.IsNotNull(hmac);
        }

#endif
        [TestMethod]
        public void PalSupportsHmacSha1()
        {
            var hmac = CryptoPal.Platform.HmacSha1(default);

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
        public void PalSupportsECDHP256()
        {
            using (var ecdh = CryptoPal.Platform.DiffieHellmanP256())
            {
                Assert.IsNotNull(ecdh);
                Assert.IsNotNull(ecdh.PublicKey);
            }
        }

        [TestMethod]
        public void PalSupportsECDHP384()
        {
            using (var ecdh = CryptoPal.Platform.DiffieHellmanP384())
            {
                Assert.IsNotNull(ecdh);
                Assert.IsNotNull(ecdh.PublicKey);
            }
        }

        [TestMethod]
        public void PalSupportsECDHP521()
        {
            using (var ecdh = CryptoPal.Platform.DiffieHellmanP521())
            {
                Assert.IsNotNull(ecdh);
                Assert.IsNotNull(ecdh.PublicKey);
            }
        }

        [TestMethod]
        public void PalSupportsDHModp14_WithImport()
        {
            var dh = CryptoPal.Platform.DiffieHellmanModp14();

            Assert.IsNotNull(dh);

            var pk = dh.PrivateKey;

            var dh2 = CryptoPal.Platform.DiffieHellmanModp14(pk);

            Assert.IsNotNull(dh2);

            Assert.IsTrue(pk.PrivateComponent.Span.SequenceEqual(dh2.PrivateKey.PrivateComponent.Span));
        }
    }
}
