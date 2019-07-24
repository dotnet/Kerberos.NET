using Kerberos.NET.Crypto;
using System;
using System.Collections.Generic;
using System.Threading;

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
            // .NET Runtime guarantees operations on variables up to the natural 
            // processor pointer size are intrinsically atomic, but there's no
            // guarantee we'll be running in a 64 bit process on a 64 bit processor
            // so maybe let's not give the system an opportunity to corrupt this

            Interlocked.Increment(ref NonceCounter);

            return (int)NonceCounter;
        }

        public static void Now(out DateTimeOffset time, out int usec)
        {
            var nowTicks = DateTimeOffset.UtcNow.Ticks;

            usec = (int)nowTicks % 1000000;

            time = new DateTimeOffset(nowTicks - usec, TimeSpan.Zero);
        }
    }
}
