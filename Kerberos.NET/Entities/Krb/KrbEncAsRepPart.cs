using Kerberos.NET.Asn1;
using Kerberos.NET.Crypto;
using System;

namespace Kerberos.NET.Entities
{
    public partial class KrbEncAsRepPart : IAsn1ApplicationEncoder<KrbEncAsRepPart>
    {
        public KrbEncAsRepPart DecodeAsApplication(ReadOnlyMemory<byte> encoded)
        {
            return DecodeApplication(encoded);
        }

        public override KeyUsage KeyUsage => KeyUsage.EncAsRepPart;
    }
}
