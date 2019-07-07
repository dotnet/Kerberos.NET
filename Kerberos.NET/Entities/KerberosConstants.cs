using Kerberos.NET.Crypto;
using System;
using System.Collections.Generic;

namespace Kerberos.NET.Entities
{
    internal static class KerberosConstants
    {
        private static long NonceCounter = DateTimeOffset.UtcNow.Ticks / 100_000_000_000L;

        public static readonly DateTimeOffset EndOfTime = new DateTimeOffset(642720196850000000, TimeSpan.Zero);

        public static IEnumerable<EncryptionType> ETypes = new[] {
            EncryptionType.AES256_CTS_HMAC_SHA1_96,
            EncryptionType.AES128_CTS_HMAC_SHA1_96,
            EncryptionType.RC4_HMAC_NT,
            EncryptionType.RC4_HMAC_NT_EXP,
            EncryptionType.RC4_HMAC_OLD_EXP
        };

        internal static int GetNonce()
        {
            NonceCounter++;

            return (int)NonceCounter;
        }
    }
}
