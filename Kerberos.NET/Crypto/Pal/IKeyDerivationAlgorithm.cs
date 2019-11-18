using System;

namespace Kerberos.NET.Crypto
{
    public interface IKeyDerivationAlgorithm
    {
        ReadOnlyMemory<byte> Derive(
            ReadOnlyMemory<byte> passwordBytes,
            ReadOnlyMemory<byte> salt,
            int iterations,
            int keySize
        );
    }
}
