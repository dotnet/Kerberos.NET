using System;
using System.Buffers.Binary;
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
            BinaryPrimitives.WriteInt32LittleEndian(bytes, val);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ConvertToBigEndian(int val, Memory<byte> memory)
        {
            ConvertToBigEndian(val, memory.Span);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ConvertToBigEndian(int val, Span<byte> bytes)
        {
            BinaryPrimitives.WriteInt32BigEndian(bytes, val);
        }
    }
}
