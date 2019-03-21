using System;

namespace Kerberos.NET
{
    [Flags]
    public enum ValidationActions
    {
        None = 0,

        ClientPrincipalIdentifier = 1 << 0,
        Realm = 1 << 1,
        TokenWindow = 1 << 2,
        StartTime = 1 << 3,
        EndTime = 1 << 4,
        Replay = 1 << 5,
        Pac = 1 << 6,

        All = ClientPrincipalIdentifier | Realm | TokenWindow | StartTime | EndTime | Replay | Pac
    }
}
