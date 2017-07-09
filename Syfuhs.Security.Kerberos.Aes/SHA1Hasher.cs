using Syfuhs.Security.Kerberos.Crypto;

namespace Syfuhs.Security.Kerberos.Aes
{
    internal class SHA1Hasher : Hasher
    {
        public SHA1Hasher()
            : base(20, 64, "SHA1")
        { }
    }
}
