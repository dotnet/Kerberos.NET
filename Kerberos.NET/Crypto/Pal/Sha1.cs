using System;
using System.Security.Cryptography;

namespace Kerberos.NET.Crypto
{
    internal class Sha1: IHashAlgorithm
    {
        public ReadOnlyMemory<byte> ComputeHash(ReadOnlySpan<byte> data)
        {
            using (var hash = SHA1.Create())
            {
                return hash.ComputeHash(data.ToArray());
            }
        }

        public void Dispose() { }
    }
}
