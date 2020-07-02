using System;
using System.Security.Cryptography.Asn1;

namespace Kerberos.NET.Entities
{
    public partial class KrbApRep
    {
        public KrbApRep()
        {
            ProtocolVersionNumber = 5;
            MessageType = MessageType.KRB_AP_REP;
        }

        public static bool CanDecode(ReadOnlyMemory<byte> encoded)
        {
            var reader = new AsnReader(encoded, AsnEncodingRules.DER);

            var tag = reader.ReadTagAndLength(out _, out _);

            return tag.HasSameClassAndValue(ApplicationTag);
        }
    }
}
