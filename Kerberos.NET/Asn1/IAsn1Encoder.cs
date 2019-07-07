using System;

namespace Kerberos.NET.Asn1
{
    public interface IAsn1Encoder
    {
        ReadOnlySpan<byte> Encode();

        object Decode(ReadOnlyMemory<byte> data);
    }
}
