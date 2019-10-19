using System;

namespace Kerberos.NET.Entities
{
    [Flags]
    public enum TicketFlags
    {
        None = -1,
        Reserved = 1 << 31,
        Forwardable = 1 << 30,
        Forwarded = 1 << 29,
        Proxiable = 1 << 28,
        Proxy = 1 << 27,
        MayPostDate = 1 << 26,
        PostDated = 1 << 25,
        Invalid = 1 << 24,
        Renewable = 1 << 23,
        Initial = 1 << 22,
        PreAuthenticated = 1 << 21,
        HardwareAuthentication = 1 << 20,
        TransitPolicyChecked = 1 << 19,
        OkAsDelegate = 1 << 18,

        EncryptedPreAuthentication = 1 << 16,
        Anonymous = 1 << 15
    }
}
