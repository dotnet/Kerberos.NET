using Kerberos.NET.Crypto;
using System;
using System.Buffers;
using System.Runtime.CompilerServices;

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
        public static long AsLong(this byte[] val)
        {
            return AsLong((ReadOnlyMemory<byte>)val);
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
        public static long AsLong(this Span<byte> val, bool littleEndian = false)
        {
            var bytes = val;

            return AsLong((ReadOnlySpan<byte>)bytes, littleEndian);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static long AsLong(this ReadOnlyMemory<byte> val, bool littleEndian = false)
        {
            return AsLong(val.Span, littleEndian);
        }
    }
}
