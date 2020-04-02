using System;
using Rfc2898DeriveBytesAlgorithm = System.Security.Cryptography.Rfc2898DeriveBytes;

namespace Kerberos.NET.Crypto
{
    internal class Rfc2898DeriveBytes : IKeyDerivationAlgorithm
    {
        public ReadOnlyMemory<byte> Derive(
            ReadOnlyMemory<byte> passwordBytes,
            ReadOnlyMemory<byte> salt,
            int iterations,
            int keySize
        )
        {
            byte[] passwordArray = passwordBytes.TryGetArrayFast();
            byte[] saltArray = salt.TryGetArrayFast();

            using (var derive = new Rfc2898DeriveBytesAlgorithm(
                passwordArray,
                saltArray,
                iterations
            ))
            {
                return derive.GetBytes(keySize);
            }
        }
    }
}
