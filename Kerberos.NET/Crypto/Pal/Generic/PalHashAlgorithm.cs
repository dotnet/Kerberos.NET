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

        public ReadOnlyMemory<byte> ComputeHash(byte[] data) => _algorithm.ComputeHash(data);

        public ReadOnlyMemory<byte> ComputeHash(ReadOnlyMemory<byte> data)
        {
            ArraySegment<byte> array = data.GetArraySegment();

            return _algorithm.ComputeHash(array.Array, array.Offset, array.Count);
        }

        public void ComputeHash(ReadOnlySpan<byte> data, Span<byte> hash)
        {
            ReadOnlyMemory<byte> buffer = ComputeHash(data.ToArray());
            buffer.Span.CopyTo(hash);
        }

        public void Dispose() => _algorithm.Dispose();
    }
}
