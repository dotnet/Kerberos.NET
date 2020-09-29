using System;

namespace Kerberos.NET.Crypto
{
    [Flags]
    public enum BCryptCreateHashFlags : int
    {
        None = 0x00000000,
        BCRYPT_HASH_REUSABLE_FLAG = 0x00000020,
    }
}
