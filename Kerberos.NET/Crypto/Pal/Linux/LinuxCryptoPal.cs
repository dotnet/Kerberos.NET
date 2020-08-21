// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

namespace Kerberos.NET.Crypto
{
    internal class LinuxCryptoPal : CryptoPal
    {
        public LinuxCryptoPal()
        {
            if (!IsLinux)
            {
                throw PlatformNotSupported();
            }
        }

#if WEAKCRYPTO
        public override IHashAlgorithm Md4() => throw PlatformNotSupported("MD4");

        public override IHashAlgorithm Md5() => new Md5();

        public override IHmacAlgorithm HmacMd5() => new HmacMd5();
#endif

        public override IHmacAlgorithm HmacSha1() => new HmacSha1();

        public override IKeyDerivationAlgorithm Rfc2898DeriveBytes() => new Rfc2898DeriveBytes();

        public override IHashAlgorithm Sha1() => new Sha1();

        public override IHashAlgorithm Sha256() => new Sha256();

        public override ISymmetricAlgorithm Aes() => new AesAlgorithm();

        public override IKeyAgreement DiffieHellmanP256() => throw PlatformNotSupported("ECDH-P256");

        public override IKeyAgreement DiffieHellmanP384() => throw PlatformNotSupported("ECDH-P384");

        public override IKeyAgreement DiffieHellmanP521() => throw PlatformNotSupported("ECDH-P521");

        public override IKeyAgreement DiffieHellmanModp2() => throw PlatformNotSupported("DH-MODP-2");

        public override IKeyAgreement DiffieHellmanModp2(IExchangeKey privateKey) => throw PlatformNotSupported("DH-MODP-2");

        public override IKeyAgreement DiffieHellmanModp14() => throw PlatformNotSupported("DH-MODP-14");

        public override IKeyAgreement DiffieHellmanModp14(IExchangeKey privateKey) => throw PlatformNotSupported("DH-MODP-14");
    }
}