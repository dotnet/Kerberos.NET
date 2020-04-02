using System.Security.Cryptography;

namespace Kerberos.NET.Crypto
{
    internal sealed class Sha256 : PalHashAlgorithm
    {
        public Sha256() : base(SHA256.Create()) { }
    }
}
