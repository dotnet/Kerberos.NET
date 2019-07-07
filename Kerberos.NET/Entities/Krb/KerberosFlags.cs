using System;

namespace Kerberos.NET.Entities
{
    [Flags]
    public enum KerberosFlags : long
    {
        Claims = 1 << 31,
        BranchAware = 1 << 30,
        ForwardToFullDc = 1 << 29
    }
}
