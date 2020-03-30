namespace Kerberos.NET.Entities
{
    public enum KerberosErrorCode
    {
        /// <summary>
        /// No error
        /// </summary>
        KDC_ERR_NONE = 0,

        /// <summary>
        /// Client's entry in database has expired
        /// </summary>
        KDC_ERR_NAME_EXP = 1,

        /// <summary>
        /// Server's entry in database has expired
        /// </summary>
        KDC_ERR_SERVICE_EXP = 2,

        /// <summary>
        /// Requested protocol version number not supported
        /// </summary>
        KDC_ERR_BAD_PVNO = 3,

        /// <summary>
        /// Client's key encrypted in old master key
        /// </summary>
        KDC_ERR_C_OLD_MAST_KVNO = 4,

        /// <summary>
        /// Server's key encrypted in old master key
        /// </summary>
        KDC_ERR_S_OLD_MAST_KVNO = 5,

        /// <summary>
        /// Client not found in Kerberos database
        /// </summary>
        KDC_ERR_C_PRINCIPAL_UNKNOWN = 6,

        /// <summary>
        /// Server not found in Kerberos database
        /// </summary>
        KDC_ERR_S_PRINCIPAL_UNKNOWN = 7,

        /// <summary>
        /// Multiple principal entries in database
        /// </summary>
        KDC_ERR_PRINCIPAL_NOT_UNIQUE = 8,

        /// <summary>
        /// The client or server has a null key
        /// </summary>
        KDC_ERR_NULL_KEY = 9,

        /// <summary>
        /// Ticket not eligible for postdating
        /// </summary>
        KDC_ERR_CANNOT_POSTDATE = 10,

        /// <summary>
        /// Requested starttime is later than end time
        /// </summary>
        KDC_ERR_NEVER_VALID = 11,

        /// <summary>
        /// KDC policy rejects request
        /// </summary>
        KDC_ERR_POLICY = 12,

        /// <summary>
        /// KDC cannot accommodate requested option
        /// </summary>
        KDC_ERR_BADOPTION = 13,

        /// <summary>
        /// KDC has no support for encryption type
        /// </summary>
        KDC_ERR_ETYPE_NOSUPP = 14,

        /// <summary>
        /// KDC has no support for checksum type
        /// </summary>
        KDC_ERR_SUMTYPE_NOSUPP = 15,

        /// <summary>
        /// KDC has no support for padata type
        /// </summary>
        KDC_ERR_PADATA_TYPE_NOSUPP = 16,

        /// <summary>
        /// KDC has no support for transited type
        /// </summary>
        KDC_ERR_TRTYPE_NOSUPP = 17,

        /// <summary>
        /// Clients credentials have been revoked
        /// </summary>
        KDC_ERR_CLIENT_REVOKED = 18,

        /// <summary>
        /// Credentials for server have been revoked
        /// </summary>
        KDC_ERR_SERVICE_REVOKED = 19,

        /// <summary>
        /// TGT has been revoked
        /// </summary>
        KDC_ERR_TGT_REVOKED = 20,

        /// <summary>
        /// Client not yet valid; try again later
        /// </summary>
        KDC_ERR_CLIENT_NOTYET = 21,

        /// <summary>
        /// Server not yet valid; try again later
        /// </summary>
        KDC_ERR_SERVICE_NOTYET = 22,

        /// <summary>
        /// Password has expired; change password to reset
        /// </summary>
        KDC_ERR_KEY_EXPIRED = 23,

        /// <summary>
        /// Pre-authentication information was invalid
        /// </summary>
        KDC_ERR_PREAUTH_FAILED = 24,

        /// <summary>
        /// Additional pre-authentication required
        /// </summary>
        KDC_ERR_PREAUTH_REQUIRED = 25,

        /// <summary>
        /// Requested server and ticket don't match
        /// </summary>
        KDC_ERR_SERVER_NOMATCH = 26,

        /// <summary>
        /// Server principal valid for user2user only
        /// </summary>
        KDC_ERR_MUST_USE_USER2USER = 27,

        /// <summary>
        /// KDC Policy rejects transited path
        /// </summary>
        KDC_ERR_PATH_NOT_ACCEPTED = 28,

        /// <summary>
        /// A service is not available
        /// </summary>
        KDC_ERR_SVC_UNAVAILABLE = 29,

        /// <summary>
        /// Integrity check on decrypted field failed
        /// </summary>
        KRB_AP_ERR_BAD_INTEGRITY = 31,

        /// <summary>
        /// Ticket expired
        /// </summary>
        KRB_AP_ERR_TKT_EXPIRED = 32,

        /// <summary>
        /// Ticket not yet valid
        /// </summary>
        KRB_AP_ERR_TKT_NYV = 33,

        /// <summary>
        /// Request is a replay
        /// </summary>
        KRB_AP_ERR_REPEAT = 34,

        /// <summary>
        /// The ticket isn't for us
        /// </summary>
        KRB_AP_ERR_NOT_US = 35,

        /// <summary>
        /// Ticket and authenticator don't match
        /// </summary>
        KRB_AP_ERR_BADMATCH = 36,

        /// <summary>
        /// Clock skew too great
        /// </summary>
        KRB_AP_ERR_SKEW = 37,

        /// <summary>
        /// Incorrect net address
        /// </summary>
        KRB_AP_ERR_BADADDR = 38,

        /// <summary>
        /// Protocol version mismatch
        /// </summary>
        KRB_AP_ERR_BADVERSION = 39,

        /// <summary>
        /// Invalid msg type
        /// </summary>
        KRB_AP_ERR_MSG_TYPE = 40,

        /// <summary>
        /// Message stream modified
        /// </summary>
        KRB_AP_ERR_MODIFIED = 41,

        /// <summary>
        /// Message out of order
        /// </summary>
        KRB_AP_ERR_BADORDER = 42,

        /// <summary>
        /// Specified version of key is not available
        /// </summary>
        KRB_AP_ERR_BADKEYVER = 44,

        /// <summary>
        /// Service key not available
        /// </summary>
        KRB_AP_ERR_NOKEY = 45,

        /// <summary>
        /// Mutual authentication failed
        /// </summary>
        KRB_AP_ERR_MUT_FAIL = 46,

        /// <summary>
        /// Incorrect message direction
        /// </summary>
        KRB_AP_ERR_BADDIRECTION = 47,

        /// <summary>
        /// Alternative authentication method required
        /// </summary>
        KRB_AP_ERR_METHOD = 48,

        /// <summary>
        /// Incorrect sequence number in message
        /// </summary>
        KRB_AP_ERR_BADSEQ = 49,

        /// <summary>
        /// Inappropriate type of checksum in message
        /// </summary>
        KRB_AP_ERR_INAPP_CKSUM = 50,

        /// <summary>
        /// Policy rejects transited path
        /// </summary>
        KRB_AP_PATH_NOT_ACCEPTED = 51,

        /// <summary>
        /// Response too big for UDP; retry with TCP
        /// </summary>
        KRB_ERR_RESPONSE_TOO_BIG = 52,

        /// <summary>
        /// Generic error
        /// </summary>
        KRB_ERR_GENERIC = 60,

        /// <summary>
        /// Field is too long for this implementation
        /// </summary>
        KRB_ERR_FIELD_TOOLONG = 61,

        /// <summary>
        /// The KDC evaluated the client certificate and does not accept it
        /// </summary>
        KDC_ERR_CLIENT_NOT_TRUSTED = 62,

        /// <summary>
        /// The certificate used by the KDC is not trusted
        /// </summary>
        KDC_ERR_KDC_NOT_TRUSTED = 63,

        /// <summary>
        /// The signature of the request signed by client private key is invalid
        /// </summary>
        KDC_ERR_INVALID_SIG = 64,

        /// <summary>
        /// KDC policy has determined the provided Diffie-Hellman key parameters are not acceptable
        /// </summary>
        KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED = 65,

        /// <summary>
        /// Reserved for PKINIT
        /// </summary>
        KDC_ERR_CERTIFICATE_MISMATCH = 66,

        /// <summary>
        /// No TGT available to validate USER-TO-USER
        /// </summary>
        KRB_AP_ERR_NO_TGT = 67,

        /// <summary>
        /// Reserved for future use
        /// </summary>
        KDC_ERR_WRONG_REALM = 68,

        /// <summary>
        /// Ticket must be for USER-TO-USER
        /// </summary>
        KRB_AP_ERR_USER_TO_USER_REQUIRED = 69,

        /// <summary>
        /// Reserved for PKINIT
        /// </summary>
        KDC_ERR_CANT_VERIFY_CERTIFICATE = 70,

        /// <summary>
        /// Reserved for PKINIT
        /// </summary>
        KDC_ERR_INVALID_CERTIFICATE = 71,

        /// <summary>
        /// Reserved for PKINIT
        /// </summary>
        KDC_ERR_REVOKED_CERTIFICATE = 72,

        /// <summary>
        /// Reserved for PKINIT
        /// </summary>
        KDC_ERR_REVOCATION_STATUS_UNKNOWN = 73,

        /// <summary>
        /// Reserved for PKINIT
        /// </summary>
        KDC_ERR_REVOCATION_STATUS_UNAVAILABLE = 74,

        /// <summary>
        /// Reserved for PKINIT
        /// </summary>
        KDC_ERR_CLIENT_NAME_MISMATCH = 75,

        /// <summary>
        /// Reserved for PKINIT
        /// </summary>
        KDC_ERR_KDC_NAME_MISMATCH = 76,

        /// <summary>
        /// The client certificate does not contain the KeyPurposeId EKU and is required
        /// </summary>
        KDC_ERR_INCONSISTENT_KEY_PURPOSE = 77,

        /// <summary>
        /// The signature algorithm used to sign the CA certificate is not accepted
        /// </summary>
        KDC_ERR_DIGEST_IN_CERT_NOT_ACCEPTED = 78,

        /// <summary>
        /// The client did not include the required paChecksum parameter
        /// </summary>
        KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED = 79,

        /// <summary>
        /// The signature algorithm used to sign the request is not accepted
        /// </summary>
        KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED = 80,

        /// <summary>
        /// The KDC does not support public key encryption for PKINIT
        /// </summary>
        KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED = 81,
    }
}
