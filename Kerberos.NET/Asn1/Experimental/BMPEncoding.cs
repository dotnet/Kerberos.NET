// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace System.Security.Cryptography.Asn1
{
    /// <summary>
    ///   Big-Endian UCS-2 encoding (the same as UTF-16BE, but disallowing surrogate pairs to leave plane 0)
    /// </summary>
    // T-REC-X.690-201508 sec 8.23.8 says to see ISO/IEC 10646:2003 section 13.1.
    // ISO/IEC 10646:2003 sec 13.1 says each character is represented by "two octets".
    // ISO/IEC 10646:2003 sec 6.3 says that when serialized as octets to use big endian.
    [ExcludeFromCodeCoverage]
    internal class BMPEncoding : SpanBasedEncoding
    {
        protected override int GetBytes(ReadOnlySpan<char> chars, Span<byte> bytes, bool write)
        {
            if (chars.IsEmpty)
            {
                return 0;
            }

            int writeIdx = 0;

            for (int i = 0; i < chars.Length; i++)
            {
                char c = chars[i];

                if (char.IsSurrogate(c))
                {
                    this.EncoderFallback.CreateFallbackBuffer().Fallback(c, i);

                    Debug.Fail("Fallback should have thrown");
                    throw new CryptographicException();
                }

                ushort val16 = c;

                if (write)
                {
                    bytes[writeIdx + 1] = (byte)val16;
                    bytes[writeIdx] = (byte)(val16 >> 8);
                }

                writeIdx += 2;
            }

            return writeIdx;
        }

        protected override int GetChars(ReadOnlySpan<byte> bytes, Span<char> chars, bool write)
        {
            if (bytes.IsEmpty)
            {
                return 0;
            }

            if (bytes.Length % 2 != 0)
            {
                this.DecoderFallback.CreateFallbackBuffer().Fallback(
                    bytes.Slice(bytes.Length - 1).ToArray(),
                    bytes.Length - 1);

                Debug.Fail("Fallback should have thrown");
                throw new CryptographicException();
            }

            int writeIdx = 0;

            for (int i = 0; i < bytes.Length; i += 2)
            {
                int val = bytes[i] << 8 | bytes[i + 1];
                char c = (char)val;

                if (char.IsSurrogate(c))
                {
                    this.DecoderFallback.CreateFallbackBuffer().Fallback(
                        bytes.Slice(i, 2).ToArray(),
                        i);

                    Debug.Fail("Fallback should have thrown");
                    throw new CryptographicException();
                }

                if (write)
                {
                    chars[writeIdx] = c;
                }

                writeIdx++;
            }

            return writeIdx;
        }

        public override int GetMaxByteCount(int charCount)
        {
            checked
            {
                return charCount * 2;
            }
        }

        public override int GetMaxCharCount(int byteCount)
        {
            return byteCount / 2;
        }
    }
}
