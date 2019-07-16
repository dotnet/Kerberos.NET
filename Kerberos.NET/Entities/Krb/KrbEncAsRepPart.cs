using System;
using System.Security.Cryptography.Asn1;
using Kerberos.NET.Asn1;

namespace Kerberos.NET.Entities
{
    public partial class KrbEncAsRepPart
    {
        internal const int ApplicationTagValue = 25;
        private static readonly Asn1Tag ApplicationTag = new Asn1Tag(TagClass.Application, ApplicationTagValue);

        public ReadOnlyMemory<byte> EncodeAsApplication()
        {
            using (var writer = new AsnWriter(AsnEncodingRules.DER))
            {
                writer.PushSequence(ApplicationTag);

                this.EncAsRepPart.Encode(writer);

                writer.PopSequence(ApplicationTag);

                var span = writer.EncodeAsSpan();

                return span.AsMemory();
            }
        }
    }
}
