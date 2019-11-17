using System;
using static Kerberos.NET.BinaryExtensions;
using Rfc2898DeriveBytesAlgorithm = System.Security.Cryptography.Rfc2898DeriveBytes;

namespace Kerberos.NET.Crypto
{
    internal class Rfc2898DeriveBytes : IKeyDerivationAlgorithm
    {
        public ReadOnlySpan<byte> Derive(
            ReadOnlyMemory<byte> passwordBytes,
            ReadOnlyMemory<byte> salt,
            int iterations,
            int keySize
        )
        {
            var passwordArray = TryGetArrayFast(passwordBytes);
            var saltArray = TryGetArrayFast(salt);

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
