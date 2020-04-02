using System;
using System.Diagnostics;
using System.Security.Cryptography;

namespace Kerberos.NET.Crypto
{
    internal abstract class PalHashAlgorithm : IHashAlgorithm
    {
        protected readonly HashAlgorithm _algorithm;

        protected PalHashAlgorithm(HashAlgorithm algorithm)
        {
            Debug.Assert(algorithm != null);

            _algorithm = algorithm;
        }

        public ReadOnlyMemory<byte> ComputeHash(ReadOnlySpan<byte> data) => _algorithm.ComputeHash(data.ToArray());
        public void Dispose() => _algorithm.Dispose();
    }
}
