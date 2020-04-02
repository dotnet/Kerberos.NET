using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Kerberos.NET
{
    internal static class BinaryExtensions
    {
        public static byte[] TryGetArrayFast(this ReadOnlyMemory<byte> bytes)
        {
            if (MemoryMarshal.TryGetArray(bytes, out ArraySegment<byte> segment) && segment.Array.Length == bytes.Length)
            {
                return segment.Array;
            }

            return bytes.ToArray();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ArraySegment<byte> GetArraySegment(this ReadOnlyMemory<byte> bytes)
        {
            if (MemoryMarshal.TryGetArray(bytes, out ArraySegment<byte> segment))
            {
                return segment;
            }

            return GetArraySegmentSlow(bytes);
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static ArraySegment<byte> GetArraySegmentSlow(ReadOnlyMemory<byte> bytes)
        {
            return new ArraySegment<byte>(bytes.ToArray());
        }
    }
}
