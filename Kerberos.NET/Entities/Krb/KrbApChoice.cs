using System;
using System.Security.Cryptography.Asn1;

namespace Kerberos.NET.Entities
{
    public partial struct KrbApChoice
    {
        private static readonly Asn1Tag KrbApReqTag = new Asn1Tag(TagClass.Application, 14);

        private static readonly Asn1Tag KrbApRepTag = new Asn1Tag(TagClass.Application, 15);

        public static bool CanDecode(ReadOnlyMemory<byte> encoded)
        {
            var reader = new AsnReader(encoded, AsnEncodingRules.DER);

            var tag = reader.ReadTagAndLength(out _, out _);

            return tag.HasSameClassAndValue(KrbApReqTag) ||
                   tag.HasSameClassAndValue(KrbApRepTag);
        }
    }
}
