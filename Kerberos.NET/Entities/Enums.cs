namespace Kerberos.NET.Entities
{
    public enum KeyUsage
    {
        KU_UNKNOWN = 0,                     // Cannot be 0
        KU_PA_ENC_TS = 1,                   // KrbAsReq
        KU_TICKET = 2,                     // KrbApReq (ticket)
        KU_ENC_AS_REP_PART = 3,             // KrbAsRep
        KU_TGS_REQ_AUTH_DATA_SESSKEY = 4,    // KrbTgsReq
        KU_TGS_REQ_AUTH_DATA_SUBKEY = 5,    // KrbTgsReq
        KU_PA_TGS_REQ_CKSUM = 6,            // KrbTgsReq
        KU_PA_TGS_REQ_AUTHENTICATOR = 7,    // KrbApReq
        KU_ENC_TGS_REP_PART_SESSKEY = 8,    // KrbTgsRep
        KU_ENC_TGS_REP_PART_SUBKEY = 9,     // KrbTgsRep
        KU_AUTHENTICATOR_CKSUM = 10,
        KU_AP_REQ_AUTHENTICATOR = 11,       // KrbApReq
        KU_ENC_AP_REP_PART = 12,            // KrbApRep
        KU_ENC_KRB_PRIV_PART = 13,          // KrbPriv
        KU_ENC_KRB_CRED_PART = 14,          // KrbCred
        KU_KRB_SAFE_CKSUM = 15,             // KrbSafe
        KU_PA_FOR_USER_ENC_CKSUM = 17,      // S4U2user
        KU_AD_KDC_ISSUED_CKSUM = 19
    }

    public enum MessageType
    {
        KRB_AS_REQ = 10, // Request for initial authentication
        KRB_AS_REP = 11, // Response to KRB_AS_REQ request
        KRB_TGS_REQ = 12, // Request for authentication based on TGT
        KRB_TGS_REP = 13, // Response to KRB_TGS_REQ request
        KRB_AP_REQ = 14, // Application request to server
        KRB_AP_REP = 15, // Response to KRB_AP_REQ_MUTUAL
        KRB_RESERVED16 = 16, // Reserved for user-to-user krb_tgt_request
        KRB_RESERVED17 = 17, // Reserved for user-to-user krb_tgt_reply
        KRB_SAFE = 20, // Safe (checksummed) application message
        KRB_PRIV = 21, // Private (encrypted) application message
        KRB_CRED = 22, // Private (encrypted) message to forward credentials
        KRB_ERROR = 30, // Error response
    }

    public enum EncryptionType
    {
        NULL = 0,
        DES_CBC_CRC = 1,
        DES_CBC_MD4 = 2,
        DES_CBC_MD5 = 3,
        AES128_CTS_HMAC_SHA1_96 = 17,
        AES256_CTS_HMAC_SHA1_96 = 18,
        DES_CBC_MD5_NT = 20,
        RC4_HMAC_NT = 23,
        RC4_HMAC_NT_EXP = 24,
        RC4_MD4 = -128,
        RC4_PLAIN2 = -129,
        RC4_LM = -130,
        RC4_SHA = -131,
        DES_PLAIN = -132,
        RC4_HMAC_OLD = -133,
        RC4_PLAIN_OLD = -134,
        RC4_HMAC_OLD_EXP = -135,
        RC4_PLAIN_OLD_EXP = -136,
        RC4_PLAIN = -140,
        RC4_PLAIN_EXP = -141,
        AES128_CTS_HMAC_SHA1_96_PLAIN = -148,
        AES256_CTS_HMAC_SHA1_96_PLAIN = -149
    }

    public enum APOptions : uint
    {
        // X X X X X X X X X X X X X X X X X X X X X X X X X X X X X X X X
        // 1 0 0
        // 0 1 0
        // 0 0 1
        RESERVED = 0,
        USE_SESSION_KEY = 1 << 30,
        MUTUAL_REQUIRED = 1 << 29
    }

    public enum PrincipalNameType : long
    {
        NT_UNKNOWN = 0,
        NT_PRINCIPAL = 1,
        NT_SRV_INST = 2,
        NT_SRV_HST = 3,
        NT_SRV_XHST = 4,
        NT_UID = 5,
        NT_X500_PRINCIPAL = 6,
        NT_SMTP_NAME = 7,
        NT_ENTERPRISE = 10
    }
}
