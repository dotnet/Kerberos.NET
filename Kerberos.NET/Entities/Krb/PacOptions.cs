using System;

namespace Kerberos.NET.Entities
{
    [Flags]
    public enum PacOptions 
    {
        Claims = 1 << 31,
        BranchAware = 1 << 30,
        ForwardToFullDc = 1 << 29,
        ResourceBasedConstrainedDelegation = 1 << 28
    }
}
