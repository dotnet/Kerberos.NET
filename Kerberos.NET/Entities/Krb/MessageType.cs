namespace Kerberos.NET.Entities
{
    public enum MessageType : long
    {
        // Request for initial authentication
        KRB_AS_REQ = 10,

        // Response to KRB_AS_REQ request
        KRB_AS_REP = 11,

        // Request for authentication based on TGT
        KRB_TGS_REQ = 12,

        // Response to KRB_TGS_REQ request
        KRB_TGS_REP = 13,

        // Application request to server
        KRB_AP_REQ = 14,

        // Response to KRB_AP_REQ_MUTUAL
        KRB_AP_REP = 15,

        // Reserved for user-to-user krb_tgt_request
        KRB_RESERVED16 = 16,

        // Reserved for user-to-user krb_tgt_reply
        KRB_RESERVED17 = 17,

        // Safe (checksummed) application message
        KRB_SAFE = 20,

        // Private (encrypted) application message
        KRB_PRIV = 21,

        // Private (encrypted) message to forward credentials
        KRB_CRED = 22,

        // Error response
        KRB_ERROR = 30
    }
}
