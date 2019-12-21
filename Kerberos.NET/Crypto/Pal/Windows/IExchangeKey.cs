using System;

namespace Kerberos.NET.Crypto
{
    public interface IExchangeKey
    {
        int KeyLength { get; set; }
        ReadOnlyMemory<byte> Private { get; set; }
        ReadOnlyMemory<byte> Public { get; set; }
        AsymmetricKeyType Type { get; set; }
    }
}