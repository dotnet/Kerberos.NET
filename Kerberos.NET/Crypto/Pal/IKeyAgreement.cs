using System;

namespace Kerberos.NET.Crypto
{
    public interface IKeyAgreement : IDisposable
    {
        IExchangeKey PublicKey { get; }

        IExchangeKey PrivateKey { get; }

        ReadOnlyMemory<byte> GenerateAgreement();

        void ImportPartnerKey(IExchangeKey publicKey);
    }
}
