using System;
using System.Collections.Generic;
using System.Security.Cryptography.Asn1;

namespace Kerberos.NET.Asn1.Entities
{
    public partial struct KrbError
    {
        public IEnumerable<KrbPaData> DecodePreAuthentication()
        {
            if (ErrorCode != KerberosErrorCode.KDC_ERR_PREAUTH_REQUIRED)
            {
                throw new InvalidOperationException($"Cannot parse PaData because error is {ErrorCode}");
            }

            var krbMethod = KrbMethodData.Decode(EData.Value, AsnEncodingRules.DER);

            return krbMethod.MethodData;
        }
    }
}
