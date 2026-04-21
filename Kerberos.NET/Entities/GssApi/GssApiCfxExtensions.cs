// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Buffers.Binary;

namespace Kerberos.NET.Entities
{
    /// <summary>
    /// Encodes and decodes GSS-API CFX extensions per RFC 6542.
    /// Extensions are binary TLV: 4-byte big-endian type, 4-byte big-endian length, then data.
    /// Multiple extensions are concatenated.
    /// </summary>
    public static class GssApiCfxExtensions
    {
        public static ReadOnlyMemory<byte> Encode(int extType, ReadOnlyMemory<byte> extData)
        {
            var result = new byte[4 + 4 + extData.Length];

            BinaryPrimitives.WriteInt32BigEndian(result.AsSpan(0, 4), extType);
            BinaryPrimitives.WriteInt32BigEndian(result.AsSpan(4, 4), extData.Length);

            extData.Span.CopyTo(result.AsSpan(8));

            return result;
        }

        public static (int type, ReadOnlyMemory<byte> data) Decode(ReadOnlyMemory<byte> encoded)
        {
            return FindExtension(encoded, extTypeFilter: null);
        }

        /// <summary>
        /// Searches the extensions blob for a specific extension type.
        /// </summary>
        public static (int type, ReadOnlyMemory<byte> data) FindExtension(
            ReadOnlyMemory<byte> encoded,
            int? extTypeFilter)
        {
            var span = encoded.Span;
            int offset = 0;

            while (offset + 8 <= span.Length)
            {
                int extType = BinaryPrimitives.ReadInt32BigEndian(span.Slice(offset, 4));
                int extLen = BinaryPrimitives.ReadInt32BigEndian(span.Slice(offset + 4, 4));

                if (offset + 8 + extLen > span.Length)
                {
                    throw new InvalidOperationException("GSS-API CFX extension length exceeds available data.");
                }

                if (!extTypeFilter.HasValue || extType == extTypeFilter.Value)
                {
                    return (extType, encoded.Slice(offset + 8, extLen));
                }

                offset += 8 + extLen;
            }

            throw new InvalidOperationException($"GSS-API CFX extension type {extTypeFilter} not found.");
        }
    }
}
