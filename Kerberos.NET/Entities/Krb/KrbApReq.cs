using System;
using System.Security.Cryptography.Asn1;

namespace Kerberos.NET.Entities
{
    public partial class KrbApReq
    {
        public KrbApReq()
        {
            ProtocolVersionNumber = 5;
            MessageType = MessageType.KRB_AP_REQ;
        }

        private static readonly Asn1Tag ApplicationTag = new Asn1Tag(TagClass.Application, 14);

        public ReadOnlyMemory<byte> EncodeAsApplication()
        {
            var writer = new AsnWriter(AsnEncodingRules.DER);

            writer.PushSequence(ApplicationTag);

            this.Encode(writer);

            writer.PopSequence(ApplicationTag);

            var span = writer.EncodeAsSpan();

            return new ReadOnlyMemory<byte>(span.ToArray());
        }
    }
}
