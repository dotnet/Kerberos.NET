﻿// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using Kerberos.NET.Crypto;

namespace Kerberos.NET.Entities
{
    internal static class KerberosConstants
    {
        private const int TickUSec = 1000000;

        private static readonly RandomNumberGenerator Rng = RandomNumberGenerator.Create();
        public static readonly DateTimeOffset EndOfTime = new DateTimeOffset(642720196850000000, TimeSpan.Zero);

        public static IEnumerable<EncryptionType> ETypes = new[]
        {
            EncryptionType.AES256_CTS_HMAC_SHA1_96,
            EncryptionType.AES128_CTS_HMAC_SHA1_96,
            EncryptionType.RC4_HMAC_NT,
            EncryptionType.RC4_HMAC_NT_EXP,
            EncryptionType.RC4_HMAC_OLD_EXP
        };

        internal static IEnumerable<EncryptionType> GetPreferredETypes(IEnumerable<EncryptionType> etypes = null)
        {
            if (etypes == null)
            {
                etypes = ETypes;
            }

            foreach (var etype in etypes)
            {
                if (CryptoService.SupportsEType(etype))
                {
                    yield return etype;
                }
            }
        }

        internal static EncryptionType? GetPreferredEType(IEnumerable<EncryptionType> etypes)
        {
            foreach (var etype in etypes)
            {
                // client sent the etypes they support in preferred order

                if (CryptoService.SupportsEType(etype))
                {
                    return etype;
                }
            }

            return null;
        }

        internal static Guid GetRequestActivityId() => Guid.NewGuid();

        internal static int GetNonce()
        {
            var bytes = new byte[4];
            Rng.GetBytes(bytes);

            return BinaryPrimitives.ReadInt32BigEndian(bytes);
        }

        public static bool WithinSkew(DateTimeOffset now, DateTimeOffset ctime, int usec, TimeSpan skew)
        {
            ctime = ctime.AddTicks(usec / 10);

            var skewed = TimeSpan.FromMilliseconds(Math.Abs((now - ctime).TotalMilliseconds));

            return skewed <= skew;
        }

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
