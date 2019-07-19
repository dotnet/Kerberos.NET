
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Asn1;
using Kerberos.NET.Crypto;
using Kerberos.NET.Asn1;

namespace Kerberos.NET.Entities
{
    public partial class KrbEncTicketPart : IAsn1ApplicationEncoder<KrbEncTicketPart>
    {
        internal const int ApplicationTagValue = 3;

        private static readonly Asn1Tag ApplicationTag = new Asn1Tag(TagClass.Application, ApplicationTagValue);

        public KrbEncTicketPart DecodeAsApplication(ReadOnlyMemory<byte> data)
        {
            throw new NotImplementedException();
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
