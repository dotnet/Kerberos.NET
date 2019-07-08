using Kerberos.NET.Crypto;
using System;

namespace Kerberos.NET.Asn1
{
    public static class BitOperation
    {
        public static ReadOnlyMemory<T> AsMemory<T>(this ReadOnlySpan<T> span) => new ReadOnlyMemory<T>(span.ToArray());

        public static Memory<T> AsMemory<T>(this Span<T> span) => new Memory<T>(span.ToArray());

        public static ReadOnlySpan<byte> AsReadOnly(this Enum val)
        {
            var longVal = (object)val;

            return AsReadOnly((long)longVal);
        }

        public static ReadOnlySpan<byte> AsReadOnly(long longVal)
        {
            var bytes = new byte[4];

            Endian.ConvertToBigEndian((int)longVal, bytes, 0);

            return new ReadOnlySpan<byte>(bytes);
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

        public static long AsLong(this ReadOnlyMemory<byte> val, bool littleEndian = false)
        {
            var bytes = val.Span.ToArray();

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
    }
}
