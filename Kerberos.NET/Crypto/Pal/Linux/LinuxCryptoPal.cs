using System.Runtime.InteropServices;

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

        public override OSPlatform OSPlatform => OSPlatform.Linux;

        public override IHashAlgorithm Md4() => throw PlatformNotSupported("MD4");

        public override IHashAlgorithm Md5() => new Md5();

        public override IHmacAlgorithm HmacMd5() => new HmacMd5();

        public override IHmacAlgorithm HmacSha1() => new HmacSha1();

        public override IKeyDerivationAlgorithm Rfc2898DeriveBytes() => new Rfc2898DeriveBytes();

        public override IHashAlgorithm Sha1() => new Sha1();

        public override IHashAlgorithm Sha256() => new Sha256();

        public override ISymmetricAlgorithm Aes() => new AesAlgorithm();

        public override IKeyAgreement DiffieHellmanModp14() => throw PlatformNotSupported("DH-MODP-14");
    }
}
