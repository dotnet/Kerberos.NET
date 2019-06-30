using Kerberos.NET.Crypto;
using System;

namespace Kerberos.NET.Asn1
{
    internal static class BitOperation
    {
        public static ReadOnlySpan<byte> AsReadOnly(this Enum val)
        {
            var bytes = new byte[4];

            var longVal = (object)val;

            Endian.ConvertToBigEndian((int)((long)longVal), bytes, 0);

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
