using System;

namespace Kerberos.NET.Crypto
{
    public interface IExchangeKey
    {
        int KeyLength { get; set; }

        public DateTimeOffset? CacheExpiry { get; set; }

        ReadOnlyMemory<byte> Private { get; set; }

        ReadOnlyMemory<byte> Public { get; set; }

        KeyAgreementAlgorithm Algorithm { get; set; }

        AsymmetricKeyType Type { get; set; }

        ReadOnlyMemory<byte> EncodePublicKey();
    }
}
