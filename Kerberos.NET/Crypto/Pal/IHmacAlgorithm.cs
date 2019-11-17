using System;

namespace Kerberos.NET.Crypto
{
    public interface IHmacAlgorithm
    {
        ReadOnlyMemory<byte> ComputeHash(
            ReadOnlyMemory<byte> key,
            ReadOnlyMemory<byte> data
        );
    }
}
