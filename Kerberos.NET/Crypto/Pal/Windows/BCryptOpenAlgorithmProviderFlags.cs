using System;

namespace Kerberos.NET.Crypto
{
    [Flags]
    public enum BCryptOpenAlgorithmProviderFlags : int
    {
        None = 0x0,
        BCRYPT_ALG_HANDLE_HMAC_FLAG = 0x8,
        BCRYPT_HASH_REUSABLE_FLAG = 0x20
    }
}
