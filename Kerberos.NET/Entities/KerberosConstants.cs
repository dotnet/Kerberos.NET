using Kerberos.NET.Crypto;
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;

namespace Kerberos.NET.Entities
{
    internal static class KerberosConstants
    {
        private static readonly int Pid = System.Diagnostics.Process.GetCurrentProcess().Id;

        private static long RequestCounter = 0;

        private static long NonceCounter = DateTimeOffset.UtcNow.Ticks / 1_000_000_000L;

        public static readonly DateTimeOffset EndOfTime = new DateTimeOffset(642720196850000000, TimeSpan.Zero);

        public static IEnumerable<EncryptionType> ETypes = new[] {
            EncryptionType.AES256_CTS_HMAC_SHA1_96,
            EncryptionType.AES128_CTS_HMAC_SHA1_96,
            EncryptionType.RC4_HMAC_NT,
            EncryptionType.RC4_HMAC_NT_EXP,
            EncryptionType.RC4_HMAC_OLD_EXP
        };

        internal static Guid GetRequestActivityId()
        {
            var counter = Interlocked.Increment(ref RequestCounter);

            var b = BitConverter.GetBytes(counter);

            return new Guid(Pid, 0, 0, b[7], b[6], b[5], b[4], b[3], b[2], b[1], b[0]);
        }

        internal static int GetNonce()
        {
            // .NET Runtime guarantees operations on variables up to the natural 
            // processor pointer size are intrinsically atomic, but there's no
            // guarantee we'll be running in a 64 bit process on a 64 bit processor
            // so maybe let's not give the system an opportunity to corrupt this

            var counter = Interlocked.Increment(ref NonceCounter);

            return (int)counter;
        }

        public static bool WithinSkew(DateTimeOffset now, DateTimeOffset ctime, int usec, TimeSpan skew)
        {
            ctime = ctime.AddTicks(usec / 10);

            var skewed = TimeSpan.FromMilliseconds(Math.Abs((now - ctime).TotalMilliseconds));

            return skewed <= skew;
        }

        private const int TickUSec = 1000000;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool TimeEquals(DateTimeOffset left, DateTimeOffset right)
        {
            var leftUsec = left.Ticks % TickUSec;
            var rightUsec = right.Ticks % TickUSec;

            return leftUsec == rightUsec;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Now(out DateTimeOffset time, out int usec)
        {
            var nowTicks = DateTimeOffset.UtcNow.Ticks;

            usec = (int)nowTicks % TickUSec;

            time = new DateTimeOffset(nowTicks - usec, TimeSpan.Zero);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Now(out DateTimeOffset time, out int? usec)
        {
            Now(out time, out int usecExplicit);

            usec = usecExplicit;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ReadOnlyMemory<byte> UnicodeBytesToUtf8(byte[] str)
        {
            return Encoding.Convert(Encoding.Unicode, Encoding.UTF8, str, 0, str.Length);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ReadOnlyMemory<byte> UnicodeStringToUtf8(string str)
        {
            return UnicodeBytesToUtf8(Encoding.Unicode.GetBytes(str));
        }
    }
}
