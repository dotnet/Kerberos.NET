using System;

namespace Kerberos.NET.Crypto
{
    public interface IKeyAgreement : IDisposable
    {
        DiffieHellmanKey PublicKey { get; }

        DiffieHellmanKey PrivateKey { get; }

        ReadOnlyMemory<byte> GenerateAgreement();

        void ImportPartnerKey(DiffieHellmanKey publicKey);
    }
}
