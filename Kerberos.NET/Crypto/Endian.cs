using System;

namespace Kerberos.NET.Crypto
{
    public static class Endian
    {
        public static void ConvertToLittleEndian(int val, Memory<byte> memory)
        {
            var bytes = memory.Span;

            bytes[0] = (byte)(val & 0xFF);
            bytes[1] = (byte)((val >> 8) & 0xFF);
            bytes[2] = (byte)((val >> 16) & 0xFF);
            bytes[3] = (byte)((val >> 24) & 0xFF);
        }

        public static void ConvertToBigEndian(int val, Memory<byte> memory)
        {
            var bytes = memory.Span;

            bytes[0] = (byte)((val >> 24) & 0xff);
            bytes[1] = (byte)((val >> 16) & 0xff);
            bytes[2] = (byte)((val >> 8) & 0xff);
            bytes[3] = (byte)((val) & 0xff);
        }
    }
}