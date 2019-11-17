using System;

namespace Kerberos.NET.Crypto
{
    public interface IHashAlgorithm : IDisposable
    {
        ReadOnlyMemory<byte> ComputeHash(ReadOnlySpan<byte> data);
    }
}
