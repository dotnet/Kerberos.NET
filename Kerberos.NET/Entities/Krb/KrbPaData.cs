using System;
using System.Collections.Generic;
using System.Diagnostics;

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

            var info = KrbETypeInfo2.Decode(Value);

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

    /// <summary>
    /// Represents a key identifying the type of data in a key-value pair in a PA-Data structure.
    /// </summary>
    public enum PaDataType
    {
        /// <summary>
        /// Indicates the absense of PA-Data.
        /// </summary>
        PA_NONE = 0,

        /// <summary>
        /// In the case of requests for additional tickets (KRB_TGS_REQ),
        /// padata-value will contain an encoded AP-REQ.
        /// </summary>
        PA_TGS_REQ = 1,

        /// <summary>
        /// The PA-Data contains a timestamp encrypted the client long term key.
        /// </summary>
        PA_ENC_TIMESTAMP = 2,

        /// <summary>
        /// The padata-value for this pre-authentication type contains the salt
        /// for the string-to-key to be used by the client to obtain the key for
        /// decrypting the encrypted part of an AS-REP message.
        /// </summary>
        PA_PW_SALT = 3,

        /// <summary>
        /// Reserved.
        /// </summary>
        Reserved = 4,

        /// <summary>
        /// Deprecated. The PA-Data contains a timestamp encrypted the client long term key.
        /// </summary>
        PA_ENC_UNIX_TIME = 5,

        /// <summary>
        /// Vendor-specific for Sandia's use of SecureID.
        /// </summary>
        PA_SANDIA_SECUREID = 6,

        /// <summary>
        /// Deprecated. The PA-Data contains structures compatible with the SESAME protocol.
        /// </summary>
        PA_SESAME = 7,

        /// <summary>
        /// Deprecated. The PA-Data contains structures compatible with OSF-DCE security protocol.
        /// </summary>
        PA_OSF_DCE = 8,

        /// <summary>
        /// Vendor-specific for the Cybersafe SecureID implementation.
        /// </summary>
        PA_CYBERSAFE_SECUREID = 9,

        /// <summary>
        /// The PA-Data contains salts used by the AFS3 system.
        /// </summary>
        PA_AFS3_SALT = 10,

        /// <summary>
        /// The PA-Data contains EType information for pre-authentication.
        /// </summary>
        PA_ETYPE_INFO = 11,

        /// <summary>
        /// Deprecated. The PA-Data contains a SAM/OTP Challenge request.
        /// </summary>
        PA_SAM_CHALLENGE = 12,

        /// <summary>
        /// Deprecated. The PA-Data contains a SAM/OTP Challenge response.
        /// </summary>
        PA_SAM_RESPONSE = 13,

        /// <summary>
        /// Deprecated. The PA-DATA contains a PKINIT request.
        /// </summary>
        PA_PK_AS_REQ_OLD = 14,

        /// <summary>
        /// Deprecated. The PA-Data contains a PKINIT response.
        /// </summary>
        PA_PK_AS_REP_OLD = 15,

        /// <summary>
        /// The PA-Data contains a PKINIT request.
        /// </summary>
        PA_PK_AS_REQ = 16,

        /// <summary>
        /// The PA-Data contains a PKINIT response.
        /// </summary>
        PA_PK_AS_REP = 17,

        /// <summary>
        /// The PA-Data contains extended EType information for pre-authentication.
        /// </summary>
        PA_ETYPE_INFO2 = 19,
        // Deprecated: 
        // PA_USE_SPECIFIED_KVNO = 20,

        /// <summary>
        /// The PA-Data contains realm referral hints to aid clients in resolving referred KDCs.
        /// </summary>
        PA_SVR_REFERRAL_INFO = 20,

        /// <summary>
        /// Deprecated. The PA-Data contains a SAM/OTP Challenge request.
        /// </summary>
        PA_SAM_REDIRECT = 21,

        /// <summary>
        /// Deprecated.
        /// </summary>
        PA_GET_FROM_TYPED_DATA = 22,

        /// <summary>
        /// Deprecated. Embedded in typed data.
        /// </summary>
        TD_PADATA = 22,

        /// <summary>
        /// Deprecated. The PA-Data contains SAM-specific EType information.
        /// </summary>
        PA_SAM_ETYPE_INFO = 23,

        /// <summary>
        /// Deprecated. The PA-Data contains an alternate principal name to be used instead of the named principal in the request.
        /// </summary>
        PA_ALT_PRINC = 24,

        /// <summary>
        /// Deprecated. The PA-Data contains a SAM/OTP Challenge request.
        /// </summary>
        PA_SAM_CHALLENGE2 = 30,

        /// <summary>
        /// Deprecated. The PA-Data contains a SAM/OTP Challenge response.
        /// </summary>
        PA_SAM_RESPONSE2 = 31,

        /// <summary>
        /// Reserved for extra TGT.
        /// </summary>
        PA_EXTRA_TGT = 41,

        /// <summary>
        /// The PA-Data contains additional certificates for CMS validation.
        /// </summary>
        TD_PKINIT_CMS_CERTIFICATES = 101,

        /// <summary>
        /// The PA-Data contains a typed structure of the form KrbPrincipalName.
        /// </summary>
        TD_KRB_PRINCIPAL = 102,

        /// <summary>
        /// The PA-Data contains a typed structure of the form Realm.
        /// </summary>
        TD_KRB_REALM = 103,

        /// <summary>
        /// The PA-Data contains a typed structure of TD-TRUSTED-CERTIFIERS. 
        /// Each ExternalPrincipalIdentifier in the TD-TRUSTED-CERTIFIERS 
        /// structure identifies a CA or a CA certificate (thereby its public key) 
        /// trusted by the KDC.
        /// </summary>
        TD_TRUSTED_CERTIFIERS = 104,

        /// <summary>
        /// The PA-Data contains a typed structure of TD-INVALID-CERTIFICATES.
        /// Each ExternalPrincipalIdentifier in the TD-INVALID-CERTIFICATES 
        /// structure identifies a certificate (that was sent by the client) 
        /// with an invalid signature.
        /// </summary>
        TD_CERTIFICATE_INDEX = 105,

        /// <summary>
        /// The PA-Data contains an application specific error.
        /// </summary>
        TD_APP_DEFINED_ERROR = 106,

        /// <summary>
        /// The PA-Data contains a nonce in the form of an Integer.
        /// </summary>
        TD_REQ_NONCE = 107,

        /// <summary>
        /// The PA-Data contains a sequence number for the request.
        /// </summary>
        TD_REQ_SEQ = 108,

        /// <summary>
        /// The PA-Data contains a pac-request structure indicating a client preference for including a PAC.
        /// </summary>
        PA_PAC_REQUEST = 128,

        /// <summary>
        /// The PA-Data contains a pa-for-user structure for 
        /// requesting delegated tickets to self or other services.
        /// </summary>
        PA_FOR_USER = 129,

        /// <summary>
        /// The PA-Data contains a pa-for-user structure containing an X509 certificate 
        /// for requesting delegated tickets to self or other services.
        /// </summary>
        PA_FOR_X509_USER = 130,

        /// <summary>
        /// Reserved.
        /// </summary>
        PA_FOR_CHECK_DUPS = 131,

        /// <summary>
        /// Reserved.
        /// </summary>
        PA_AS_CHECKSUM = 132,

        /// <summary>
        /// The PA-Data contains a stateless cookie that is not tied to a specific KDC.
        /// </summary>
        PA_FX_COOKIE = 133,

        /// <summary>
        /// The PA-Data contains a PA-AUTHENTICATION-SET structure containing elements
        /// used to provide hints to the client about whether the authentication mechanism
        /// can be used by the client.
        /// </summary>
        PA_AUTHENTICATION_SET = 134,

        /// <summary>
        /// The PA-Data contains the encoding of the PA-AUTHENTICATION-SET sequence 
        /// received from the KDC corresponding to the authentication set that is chosen.
        /// </summary>
        PA_AUTH_SET_SELECTED = 135,

        /// <summary>
        /// The PA-Data contains a FAST Request which contains armored data for the request.
        /// </summary>
        PA_FX_FAST = 136,

        /// <summary>
        /// The PA-Data contains a FAST error structure.
        /// </summary>
        PA_FX_ERROR = 137,

        /// <summary>
        /// The PA-Data contains a FAST-encrypted challenge.
        /// </summary>
        PA_ENCRYPTED_CHALLENGE = 138,

        /// <summary>
        /// The PA-Data contains a PA-OTP-CHALLENGE containing a 
        /// server-generated nonce and information for the client on how to 
        /// generate the OTP.
        /// </summary>
        PA_OTP_CHALLENGE = 141,

        /// <summary>
        /// The PA-Data contains the DER encoding of a PA-OTP-REQUEST with the 
        /// pre-authentication data encrypted by the client using the generated 
        /// Client Key and optional information on how the OTP was generated.
        /// </summary>
        PA_OTP_REQUEST = 142,

        /// <summary>
        /// Obsolete.
        /// </summary>
        PA_OTP_CONFIRM = 143,

        /// <summary>
        /// The PA-Data contains a PA-OTP-PIN-CHANGE structure which is returned 
        /// by the KDC in the enc-fast-rep of a PA-FX-FAST-REPLY in the AS-REP if 
        /// the user must change their PIN, if the user's PIN has been changed, or 
        /// to notify the user of the PIN's expiry time.
        /// </summary>
        PA_OTP_PIN_CHANGE = 144,

        /// <summary>
        /// The PA-Data contains an AS-REQ to be used by the Extensible
        /// Pre-Authentication in Kerberos (EPAK) protocol.
        /// </summary>
        PA_EPAK_AS_REQ = 145,

        /// <summary>
        /// The PA-Data contains an AS-REQ to be used by the Extensible
        /// Pre-Authentication in Kerberos (EPAK) protocol.
        /// </summary>
        PA_EPAK_AS_REP = 146,

        /// <summary>
        /// The PA-Data contains an EncryptedData structure containing a
        /// randomly generated key for the KDC contribution key.
        /// </summary>
        PA_PKINIT_KX = 147,

        /// <summary>
        /// The PA-Data contains an InitiatorNameAssertion for the PKU2U protocol.
        /// </summary>
        PA_PKU2U_NAME = 148,

        /// <summary>
        /// The PA-Data contains the FAST checksum computed over the 
        /// type AS-REQ or TGS-REQ in the request.
        /// </summary>
        PA_REQ_ENC_PA_REP = 149,

        /// <summary>
        /// The PA-Data contains a PA-SUPPORTED-ENCTYPES structure 
        /// which specifies the encryption  types supported and contains 
        /// a bit field of the supported encryption types bit flags.
        /// </summary>
        PA_SUPPORTED_ETYPES = 165,

        /// <summary>
        /// The PA-Data contains a PA-PAC-OPTIONS structure which 
        /// specifies explicitly requested options in the PAC.
        /// </summary>
        PA_PAC_OPTIONS = 167
    }
}
