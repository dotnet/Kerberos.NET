using System;
using System.Runtime.CompilerServices;

namespace Kerberos.NET.Crypto
{
    public static class Endian
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ConvertToLittleEndian(int val, Memory<byte> memory)
        {
            ConvertToLittleEndian(val, memory.Span);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ConvertToLittleEndian(int val, Span<byte> bytes)
        {
            bytes[0] = (byte)(val & 0xFF);
            bytes[1] = (byte)((val >> 8) & 0xFF);
            bytes[2] = (byte)((val >> 16) & 0xFF);
            bytes[3] = (byte)((val >> 24) & 0xFF);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ConvertToBigEndian(int val, Memory<byte> memory)
        {
            ConvertToBigEndian(val, memory.Span);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ConvertToBigEndian(int val, Span<byte> bytes)
        {
            bytes[0] = (byte)((val >> 24) & 0xff);
            bytes[1] = (byte)((val >> 16) & 0xff);
            bytes[2] = (byte)((val >> 8) & 0xff);
            bytes[3] = (byte)((val) & 0xff);
        }
    }
}