using System.Security.Cryptography;

namespace Kerberos.NET.Crypto
{
    internal sealed class Sha1 : PalHashAlgorithm
    {
        public Sha1() : base(SHA1.Create()) { }
    }
}
