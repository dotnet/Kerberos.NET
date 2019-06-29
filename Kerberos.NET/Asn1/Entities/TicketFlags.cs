using System;

namespace Kerberos.NET.Asn1.Entities
{
    [Flags]
    public enum TicketFlags : long
    {
        None = -1,
        Forwardable = 0x40000000,
        Forwarded = 0x20000000,
        Proxiable = 0x10000000,
        Proxy = 0x08000000,
        MayPostDate = 0x04000000,
        PostDated = 0x02000000,
        Invalid = 0x01000000,
        Renewable = 0x00800000,
        Initial = 0x00400000,
        PreAuthenticated = 0x00200000,
        HardwareAuthentication = 0x00100000,
        TransitPolicyChecked = 0x00080000,
        OkAsDelegate = 0x00040000,
        EncryptedPreAuthentication = 0x00010000,
        Anonymous = 0x00008000
    }
}
