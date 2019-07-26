using Kerberos.NET.Crypto;
using System;
using System.Buffers;

namespace Kerberos.NET.Asn1
{
    public static class BitOperation
    {
        public static ReadOnlyMemory<T> AsMemory<T>(this ReadOnlySpan<T> span) => new ReadOnlyMemory<T>(span.ToArray());

        public static Memory<T> AsMemory<T>(this Span<T> span) => new Memory<T>(span.ToArray());

        public static ReadOnlySpan<byte> AsReadOnly(this Enum val, bool littleEndian = false)
        {
            var longVal = (object)val;

            return AsReadOnly((long)longVal, littleEndian: littleEndian);
        }

        public static ReadOnlySpan<byte> AsReadOnly(long longVal, bool littleEndian = false)
        {
            var bytes = new byte[4];

            if (littleEndian)
            {
                Endian.ConvertToLittleEndian((int)longVal, bytes);
            }
            else
            {
                Endian.ConvertToBigEndian((int)longVal, bytes);
            }

            return new ReadOnlySpan<byte>(bytes);
        }

        public static long AsLong(this ReadOnlySequence<byte> val)
        {
            return val.ToArray().AsLong();
        }

        public static int AsInt(this ReadOnlyMemory<byte> val)
        {
            var bytes = val.Span;

            int num = 0;

            for (int i = 0; i < bytes.Length; i++)
            {
                num = (num << 8) | bytes[i];
            }

            return num;
        }

        public static long AsLong(this byte[] val)
        {
            return AsLong((ReadOnlyMemory<byte>)val);
        }

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

        public static long AsLong(this Span<byte> val, bool littleEndian = false)
        {
            var bytes = val;

            return AsLong((ReadOnlySpan<byte>)bytes, littleEndian);
        }

        public static long AsLong(this ReadOnlyMemory<byte> val, bool littleEndian = false)
        {
            return AsLong(val.Span, littleEndian);
        }
    }
}
