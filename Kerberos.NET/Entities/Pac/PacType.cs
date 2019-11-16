namespace Kerberos.NET.Entities
{
    public enum PacType
    {
        LOGON_INFO = 1,
        CREDENTIAL_TYPE = 2,

        SERVER_CHECKSUM = 6,
        PRIVILEGE_SERVER_CHECKSUM = 7,

        CLIENT_NAME_TICKET_INFO = 10,

        CONSTRAINED_DELEGATION_INFO = 11,
        UPN_DOMAIN_INFO = 12,
        CLIENT_CLAIMS = 13,
        DEVICE_INFO = 14,
        DEVICE_CLAIMS = 15
    }
}
