using System;

namespace Kerberos.NET.Crypto
{
    public interface IKeyAgreement : IDisposable
    {
        ReadOnlyMemory<byte> PublicKey { get; }

        ReadOnlyMemory<byte> GenerateAgreement();

        void ImportPartnerKey(ReadOnlySpan<byte> publicKey);
    }
}
