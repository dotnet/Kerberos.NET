using Kerberos.NET.Asn1;
using System;
using System.Security.Cryptography.Asn1;

namespace Kerberos.NET.Entities
{
    public partial class KrbAsRep : IAsn1ApplicationEncoder<KrbAsRep>
    {
        internal const int ApplicationTagValue = 11;
        internal static readonly Asn1Tag ApplicationTag = new Asn1Tag(TagClass.Application, ApplicationTagValue);

        public KrbAsRep DecodeAsApplication(ReadOnlyMemory<byte> data)
        {
            return Decode(ApplicationTag, data);
        }

        public ReadOnlyMemory<byte> EncodeAsApplication()
        {
            using (var writer = new AsnWriter(AsnEncodingRules.DER))
            {
                writer.PushSequence(ApplicationTag);

                if (this.Response != null)
                {
                    this.Response.Encode(writer);
                }

                writer.PopSequence(ApplicationTag);

                var span = writer.EncodeAsSpan();

                return span.AsMemory();
            }
        }
    }
}
