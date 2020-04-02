using System;

namespace Kerberos.NET.Crypto
{
    public interface IHashAlgorithm : IDisposable
    {
        ReadOnlyMemory<byte> ComputeHash(byte[] data);
        ReadOnlyMemory<byte> ComputeHash(ReadOnlySpan<byte> data);
        ReadOnlyMemory<byte> ComputeHash(ReadOnlyMemory<byte> data);
    }
}
