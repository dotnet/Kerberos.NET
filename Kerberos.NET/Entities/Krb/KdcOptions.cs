using System;

namespace Kerberos.NET.Entities
{
    [Flags]
    public enum KdcOptions : long
    {
        Reserved = 1 << 31,
        Forwardable = 1 << 30,
        Forwarded = 1 << 29,
        Proxiable = 1 << 28,
        Proxy = 1 << 27,
        AllowPostdate = 1 << 26,
        Postdated = 1 << 25,
        Unused7 = 1 << 24,
        Renewable = 1 << 23,
        Unused9 = 1 << 22,
        Unused10 = 1 << 21,
        OptHardwareAuth = 1 << 20,
        Unused12 = 1 << 19,
        Unused13 = 1 << 18,
        ConstrainedDelegation = 1 << 17,
        Canonicalize = 1 << 16,
        RequestAnonymous = 1 << 15,
        Unused17 = 1 << 14,
        Unused18 = 1 << 13,
        Unused19 = 1 << 12,
        Unused20 = 1 << 11,
        Unused21 = 1 << 10,
        Unused22 = 1 << 9,
        Unused23 = 1 << 8,
        Unused24 = 1 << 7,
        Unused25 = 1 << 6,
        DisableTransitCheck = 1 << 5,
        RenewableOk = 1 << 4,
        EncTktInSkey = 1 << 3,
        Unused29 = 1 << 2,
        Renew = 1 << 1,
        Validate = 1 << 0,
    }
}
