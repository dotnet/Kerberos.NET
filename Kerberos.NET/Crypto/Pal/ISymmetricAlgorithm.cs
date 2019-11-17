using System;

namespace Kerberos.NET.Crypto
{
    public interface ISymmetricAlgorithm
    {
        Memory<byte> Encrypt(
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> key,
            ReadOnlySpan<byte> iv
        );

        Memory<byte> Decrypt(
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> key,
            ReadOnlySpan<byte> iv
        );
    }
}
