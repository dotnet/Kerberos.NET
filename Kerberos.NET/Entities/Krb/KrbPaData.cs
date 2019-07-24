using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Cryptography.Asn1;

namespace Kerberos.NET.Entities
{
    [DebuggerDisplay("{Type} {Value.Length}")]
    public partial class KrbPaData
    {
        public IEnumerable<KrbETypeInfo2Entry> DecodeETypeInfo2()
        {
            if (Type != PaDataType.PA_ETYPE_INFO2)
            {
                throw new InvalidOperationException($"Cannot parse EType Info because type is {Type}");
            }

            var info = KrbETypeInfo2.Decode(Value, AsnEncodingRules.DER);

            return info.ETypeInfo;
        }

        public KrbApReq DecodeApReq()
        {
            if (Type != PaDataType.PA_TGS_REQ)
            {
                throw new InvalidOperationException($"Cannot parse the TGS ApReq because type is {Type}");
            }

            return new KrbApReq().DecodeAsApplication(Value);
        }
    }

    public enum PaDataType : long
    {
        PA_TGS_REQ = 1,
        PA_ENC_TIMESTAMP = 2,
        PA_PW_SALT = 3,
        Reserved = 4,
        PA_ENC_UNIX_TIME = 5,
        PA_SANDIA_SECUREID = 6,
        PA_SESAME = 7,
        PA_OSF_DCE = 8,
        PA_CYBERSAFE_SECUREID = 9,
        PA_AFS3_SALT = 10,
        PA_ETYPE_INFO = 11,
        PA_SAM_CHALLENGE = 12,
        PA_SAM_RESPONSE = 13,
        PA_PK_AS_REQ_OLD = 14,
        PA_PK_AS_REP_OLD = 15,
        PA_PK_AS_REQ = 16,
        PA_PK_AS_REP = 17,
        PA_ETYPE_INFO2 = 19,
        PA_USE_SPECIFIED_KVNO = 20,
        PA_SAM_REDIRECT = 21,
        PA_GET_FROM_TYPED_DATA = 22,
        TD_PADATA = 22,
        PA_SAM_ETYPE_INFO = 23,
        PA_ALT_PRINC = 24,
        PA_SAM_CHALLENGE2 = 30,
        PA_SAM_RESPONSE2 = 31,
        PA_EXTRA_TGT = 41,
        TD_PKINIT_CMS_CERTIFICATES = 101,
        TD_KRB_PRINCIPAL = 102,
        TD_KRB_REALM = 103,
        TD_TRUSTED_CERTIFIERS = 104,
        TD_CERTIFICATE_INDEX = 105,
        TD_APP_DEFINED_ERROR = 106,
        TD_REQ_NONCE = 107,
        TD_REQ_SEQ = 108,
        PA_PAC_REQUEST = 128,

        // -- So sayeth Heimdal ¯\_(ツ)_/¯

        PA_FOR_USER = 129,
        PA_FOR_X509_USER = 130,
        PA_FOR_CHECK_DUPS = 131,
        PA_AS_CHECKSUM = 132,
        PA_PK_AS_09_BINDING = 132,
        PA_CLIENT_CANONICALIZED = 133,
        PA_FX_COOKIE = 133,
        PA_AUTHENTICATION_SET = 134,
        PA_AUTH_SET_SELECTED = 135,
        PA_FX_FAST = 136,
        PA_FX_ERROR = 137,
        PA_ENCRYPTED_CHALLENGE = 138,
        PA_OTP_CHALLENGE = 141,
        PA_OTP_REQUEST = 142,
        PA_OTP_CONFIRM = 143,
        PA_OTP_PIN_CHANGE = 144,
        PA_EPAK_AS_REQ = 145,
        PA_EPAK_AS_REP = 146,
        PA_PKINIT_KX = 147,
        PA_PKU2U_NAME = 148,
        PA_REQ_ENC_PA_REP = 149,
        PA_SUPPORTED_ETYPES = 165,
        PA_PAC_OPTIONS = 167
    }
}
