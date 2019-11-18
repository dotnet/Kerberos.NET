using System;

namespace Kerberos.NET.Crypto
{
    public interface ISymmetricAlgorithm
    {
        Memory<byte> Encrypt(
            ReadOnlyMemory<byte> data,
            ReadOnlyMemory<byte> key,
            ReadOnlyMemory<byte> iv
        );

        Memory<byte> Decrypt(
            ReadOnlyMemory<byte> data,
            ReadOnlyMemory<byte> key,
            ReadOnlyMemory<byte> iv
        );
    }
}
