using Kerberos.NET.Asn1;
using System;

namespace Kerberos.NET.Entities
{
    public partial class KrbEncAsRepPart : IAsn1ApplicationEncoder<KrbEncAsRepPart>
    {
        public KrbEncAsRepPart DecodeAsApplication(ReadOnlyMemory<byte> encoded)
        {
            return DecodeApplication(encoded);
        }
    }
}
