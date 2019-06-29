namespace Kerberos.NET.Asn1.Entities
{
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
