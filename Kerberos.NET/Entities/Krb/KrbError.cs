using System;
using System.Collections.Generic;
using System.Security.Cryptography.Asn1;

namespace Kerberos.NET.Entities
{
    public partial class KrbError
    {
        public KrbError()
        {
            ProtocolVersionNumber = 5;
            MessageType = MessageType.KRB_ERROR;
        }

        private static readonly Asn1Tag KrbErrorTag = new Asn1Tag(TagClass.Application, 30);

        public static bool CanDecode(ReadOnlyMemory<byte> encoded)
        {
            var reader = new AsnReader(encoded, AsnEncodingRules.DER);

            var tag = reader.ReadTagAndLength(out _, out _);

            return tag.HasSameClassAndValue(KrbErrorTag);
        }

        public IEnumerable<KrbPaData> DecodePreAuthentication()
        {
            if (ErrorCode != KerberosErrorCode.KDC_ERR_PREAUTH_REQUIRED)
            {
                throw new InvalidOperationException($"Cannot parse Pre-Auth PaData because error is {ErrorCode}");
            }

            if (!EData.HasValue)
            {
                throw new InvalidOperationException("Pre-Auth data isn't present in EData");
            }

            var krbMethod = KrbMethodData.Decode(EData.Value, AsnEncodingRules.DER);

            return krbMethod.MethodData;
        }
    }
}
