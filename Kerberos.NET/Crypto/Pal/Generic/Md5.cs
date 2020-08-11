using System.Security.Cryptography;

namespace Kerberos.NET.Crypto
{
#if WEAKCRYPTO
    internal sealed class Md5 : PalHashAlgorithm
    {
        public Md5() : base(MD5.Create()) { }
    }
#endif
}
