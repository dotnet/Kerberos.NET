using System;

namespace Kerberos.NET.Asn1
{
    public interface IAsn1ApplicationEncoder<T>
    {
        T DecodeAsApplication(ReadOnlyMemory<byte> data);

        ReadOnlyMemory<byte> EncodeAsApplication();
    }
}
