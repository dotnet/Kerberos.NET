using System;

namespace Syfuhs.Security.Kerberos
{
    [Flags]
    public enum ValidationAction
    {
        None = 0,

        ClientPrincipalIdentifier = 1 << 0,
        Realm = 1 << 1,
        TokenWindow = 1 << 2,
        StartTime = 1 << 3,
        EndTime = 1 << 4,
        Replay = 1 << 5,

        All = ClientPrincipalIdentifier | Realm | TokenWindow | StartTime | EndTime | Replay
    }
}
