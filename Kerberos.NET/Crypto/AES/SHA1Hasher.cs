using Kerberos.NET.Crypto;

namespace Kerberos.NET.Crypto.AES
{
    internal class SHA1Hasher : Hasher
    {
        public SHA1Hasher()
            : base(64, new Sha1Digest())
        { }
    }
}
