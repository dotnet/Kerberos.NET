// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace System.Security.Cryptography.Asn1
{
    /// <summary>
    /// Compatibility encoding for T61Strings. Interprets the characters as UTF-8 or
    /// ISO-8859-1 as a fallback.
    /// </summary>
    [ExcludeFromCodeCoverage]
    internal class T61Encoding : Encoding
    {
        private static readonly Encoding Utf8Encoding = new UTF8Encoding(false, throwOnInvalidBytes: true);
        private static readonly Encoding Latin1Encoding = GetEncoding("iso-8859-1");

        public override int GetByteCount(char[] chars, int index, int count)
        {
            return Utf8Encoding.GetByteCount(chars, index, count);
        }

        public override unsafe int GetByteCount(char* chars, int count)
        {
            return Utf8Encoding.GetByteCount(chars, count);
        }

        public override int GetByteCount(string s)
        {
            return Utf8Encoding.GetByteCount(s);
        }

#if netcoreapp || uap || NETCOREAPP || netstandard21
        public override int GetByteCount(ReadOnlySpan<char> chars)
        {
            return s_utf8Encoding.GetByteCount(chars);
        }
#endif

        public override int GetBytes(char[] chars, int charIndex, int charCount, byte[] bytes, int byteIndex)
        {
            return Utf8Encoding.GetBytes(chars, charIndex, charCount, bytes, byteIndex);
        }

        public override unsafe int GetBytes(char* chars, int charCount, byte* bytes, int byteCount)
        {
            return Utf8Encoding.GetBytes(chars, charCount, bytes, byteCount);
        }

        public override int GetCharCount(byte[] bytes, int index, int count)
        {
            try
            {
                return Utf8Encoding.GetCharCount(bytes, index, count);
            }
            catch (DecoderFallbackException)
            {
                return Latin1Encoding.GetCharCount(bytes, index, count);
            }
        }

        public override unsafe int GetCharCount(byte* bytes, int count)
        {
            try
            {
                return Utf8Encoding.GetCharCount(bytes, count);
            }
            catch (DecoderFallbackException)
            {
                return Latin1Encoding.GetCharCount(bytes, count);
            }
        }

#if netcoreapp || uap || NETCOREAPP || netstandard21
        public override int GetCharCount(ReadOnlySpan<byte> bytes)
        {
            try
            {
                return s_utf8Encoding.GetCharCount(bytes);
            }
            catch (DecoderFallbackException)
            {
                return s_latin1Encoding.GetCharCount(bytes);
            }
        }
#endif

        public override int GetChars(byte[] bytes, int byteIndex, int byteCount, char[] chars, int charIndex)
        {
            try
            {
                return Utf8Encoding.GetChars(bytes, byteIndex, byteCount, chars, charIndex);
            }
            catch (DecoderFallbackException)
            {
                return Latin1Encoding.GetChars(bytes, byteIndex, byteCount, chars, charIndex);
            }
        }

        public override unsafe int GetChars(byte* bytes, int byteCount, char* chars, int charCount)
        {
            try
            {
                return Utf8Encoding.GetChars(bytes, byteCount, chars, charCount);
            }
            catch (DecoderFallbackException)
            {
                return Latin1Encoding.GetChars(bytes, byteCount, chars, charCount);
            }
        }

        public override int GetMaxByteCount(int charCount)
        {
            return Utf8Encoding.GetMaxByteCount(charCount);
        }

        public override int GetMaxCharCount(int byteCount)
        {
            // Latin-1 is single byte encoding, so byteCount == charCount
            // UTF-8 is multi-byte encoding, so byteCount >= charCount
            // We want to return the maximum of those two, which happens to be byteCount.
            return byteCount;
        }
    }
}
