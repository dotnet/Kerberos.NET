using Kerberos.NET.Asn1;
using System;

namespace Kerberos.NET.Entities
{
    public partial class KrbTgsRep : IAsn1ApplicationEncoder<KrbTgsRep>
    {
        public KrbTgsRep DecodeAsApplication(ReadOnlyMemory<byte> encoded)
        {
            return DecodeApplication(encoded);
        }
    }
}
