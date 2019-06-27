namespace Kerberos.NET.Crypto
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
}
