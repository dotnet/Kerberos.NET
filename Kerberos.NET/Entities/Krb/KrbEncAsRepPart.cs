using System;
using System.Security.Cryptography.Asn1;
using Kerberos.NET.Asn1;

namespace Kerberos.NET.Entities
{
    public partial class KrbEncAsRepPart : IAsn1ApplicationEncoder<KrbEncAsRepPart>
    {
        private static readonly Asn1Tag KrbEncAsRepPartTag = new Asn1Tag(TagClass.Application, 25);

        public KrbEncAsRepPart DecodeAsApplication(ReadOnlyMemory<byte> encoded)
        {
            return DecodeApplication(encoded);
        }

        public static bool CanDecode(ReadOnlyMemory<byte> encoded)
        {
            return CanDecode(encoded, KrbEncAsRepPartTag);
        }
    }
}
