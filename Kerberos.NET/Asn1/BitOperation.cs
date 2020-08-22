// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;
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
            Debug.Assert(longVal <= int.MaxValue);

            var bytes = new Span<byte>(new byte[4]);

            if (littleEndian)
            {
                BinaryPrimitives.WriteInt32LittleEndian(bytes, (int)longVal);
            }
            else
            {
                BinaryPrimitives.WriteInt32BigEndian(bytes, (int)longVal);
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
            return AsLong(val.AsSpan(), littleEndian);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static long AsLong(this ReadOnlySpan<byte> val, bool littleEndian = false)
        {
            Debug.Assert(val.Length >= sizeof(int));

            return littleEndian
                ? BinaryPrimitives.ReadInt32LittleEndian(val)
                : BinaryPrimitives.ReadInt32BigEndian(val);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static long AsLong(this ReadOnlyMemory<byte> val, bool littleEndian = false)
        {
            return AsLong(val.Span, littleEndian);
        }
    }
}
