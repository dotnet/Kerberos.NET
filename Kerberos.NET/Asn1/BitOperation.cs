// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Buffers;
using System.Runtime.CompilerServices;
using Kerberos.NET.Crypto;

namespace Kerberos.NET
{
    public static class BitOperation
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ReadOnlyMemory<T> AsMemory<T>(this ReadOnlySpan<T> span) => new ReadOnlyMemory<T>(span.ToArray());

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ReadOnlySpan<byte> AsReadOnly(this Enum val, bool littleEndian = false)
        {
            var longVal = (object)val;

            return AsReadOnly((int)longVal, littleEndian: littleEndian);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ReadOnlySpan<byte> AsReadOnly(long longVal, bool littleEndian = false)
        {
            var bytes = new Span<byte>(new byte[4]);

            if (littleEndian)
            {
                Endian.ConvertToLittleEndian((int)longVal, bytes);
            }
            else
            {
                Endian.ConvertToBigEndian((int)longVal, bytes);
            }

            return bytes;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static long AsLong(this ReadOnlySequence<byte> val)
        {
            return val.First.Span.AsLong();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static long AsLong(this byte[] val, bool littleEndian = false)
        {
            return AsLong((ReadOnlyMemory<byte>)val, littleEndian);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static long AsLong(this ReadOnlySpan<byte> val, bool littleEndian = false)
        {
            var bytes = val.ToArray();

            if (littleEndian)
            {
                Array.Reverse(bytes);
            }

            long num = 0;

            for (int i = 0; i < bytes.Length; i++)
            {
                num = (num << 8) | bytes[i];
            }

            return num;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static long AsLong(this ReadOnlyMemory<byte> val, bool littleEndian = false)
        {
            return AsLong(val.Span, littleEndian);
        }
    }
}