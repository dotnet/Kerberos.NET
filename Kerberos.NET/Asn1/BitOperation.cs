// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Buffers.Binary;
using System.Diagnostics;

namespace Kerberos.NET
{
    public static class BitOperation
    {
        public static byte[] AsBytes(long longVal, bool littleEndian = false)
        {
            Debug.Assert(longVal <= int.MaxValue);

            var bytes = new byte[4];

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

        public static ReadOnlyMemory<byte> AsReadOnlyMemory(this Enum val, bool littleEndian = false)
        {
            var longVal = (object)val;

            return AsBytes((int)longVal, littleEndian: littleEndian);
        }

        public static ReadOnlySpan<byte> AsReadOnlySpan(this Enum val, bool littleEndian = false)
        {
            var longVal = (object)val;

            return AsBytes((int)longVal, littleEndian: littleEndian);
        }

        public static long AsLong(this byte[] val, bool littleEndian = false)
        {
            return AsLong(val.AsSpan(), littleEndian);
        }

        public static long AsLong(this ReadOnlySpan<byte> val, bool littleEndian = false)
        {
            Debug.Assert(val.Length >= sizeof(int));

            return littleEndian
                ? BinaryPrimitives.ReadInt32LittleEndian(val)
                : BinaryPrimitives.ReadInt32BigEndian(val);
        }

        public static long AsLong(this ReadOnlyMemory<byte> val, bool littleEndian = false)
        {
            return AsLong(val.Span, littleEndian);
        }
    }
}
