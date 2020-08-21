// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Kerberos.NET
{
    public static class BinaryExtensions
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static byte[] TryGetArrayFast(ReadOnlyMemory<byte> bytes)
        {
            if (MemoryMarshal.TryGetArray(bytes, out ArraySegment<byte> segment) && segment.Array.Length == bytes.Length)
            {
                return segment.Array;
            }
            else
            {
                return bytes.ToArray();
            }
        }
    }
}