using System;
using System.Security.Cryptography.Asn1;
using Kerberos.NET.Asn1;

namespace Kerberos.NET.Entities
{
    public partial class KrbTgsRep : IAsn1ApplicationEncoder<KrbTgsRep>
    {
        internal const int ApplicationTagValue = 13;
        private static readonly Asn1Tag ApplicationTag = new Asn1Tag(TagClass.Application, ApplicationTagValue);

        public KrbTgsRep DecodeAsApplication(ReadOnlyMemory<byte> encoded)
        {
            return Decode(ApplicationTag, encoded);
        }

        public ReadOnlyMemory<byte> EncodeAsApplication()
        {
            using (var writer = new AsnWriter(AsnEncodingRules.DER))
            {
                writer.PushSequence(ApplicationTag);

                this.Encode(writer);

                writer.PopSequence(ApplicationTag);

                var span = writer.EncodeAsSpan();

                return span.AsMemory();
            }
        }
    }
}
