// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace System.Security.Cryptography.Asn1
{
    [ExcludeFromCodeCoverage]
    internal abstract class SpanBasedEncoding : Encoding
    {
        protected SpanBasedEncoding()
            : base(0, EncoderFallback.ExceptionFallback, DecoderFallback.ExceptionFallback)
        {
        }

        protected abstract int GetBytes(ReadOnlySpan<char> chars, Span<byte> bytes, bool write);

        protected abstract int GetChars(ReadOnlySpan<byte> bytes, Span<char> chars, bool write);

        public override int GetByteCount(char[] chars, int index, int count)
        {
            return this.GetByteCount(new ReadOnlySpan<char>(chars, index, count));
        }

        public override unsafe int GetByteCount(char* chars, int count)
        {
            return this.GetByteCount(new ReadOnlySpan<char>(chars, count));
        }

        public override int GetByteCount(string s)
        {
            return this.GetByteCount(s.AsSpan());
        }

        public
#if netcoreapp || uap || NETCOREAPP || netstandard21
            override
#endif
        int GetByteCount(ReadOnlySpan<char> chars)
        {
            return this.GetBytes(chars, Span<byte>.Empty, write: false);
        }

        public override int GetBytes(char[] chars, int charIndex, int charCount, byte[] bytes, int byteIndex)
        {
            return this.GetBytes(
                new ReadOnlySpan<char>(chars, charIndex, charCount),
                new Span<byte>(bytes, byteIndex, bytes.Length - byteIndex),
                write: true);
        }

        public override unsafe int GetBytes(char* chars, int charCount, byte* bytes, int byteCount)
        {
            return this.GetBytes(
                new ReadOnlySpan<char>(chars, charCount),
                new Span<byte>(bytes, byteCount),
                write: true);
        }

        public override int GetCharCount(byte[] bytes, int index, int count)
        {
            return this.GetCharCount(new ReadOnlySpan<byte>(bytes, index, count));
        }

        public override unsafe int GetCharCount(byte* bytes, int count)
        {
            return this.GetCharCount(new ReadOnlySpan<byte>(bytes, count));
        }

        public
#if netcoreapp || uap || NETCOREAPP || netstandard21
            override
#endif
        int GetCharCount(ReadOnlySpan<byte> bytes)
        {
            return this.GetChars(bytes, Span<char>.Empty, write: false);
        }

        public override int GetChars(byte[] bytes, int byteIndex, int byteCount, char[] chars, int charIndex)
        {
            return this.GetChars(
                new ReadOnlySpan<byte>(bytes, byteIndex, byteCount),
                new Span<char>(chars, charIndex, chars.Length - charIndex),
                write: true);
        }

        public override unsafe int GetChars(byte* bytes, int byteCount, char* chars, int charCount)
        {
            return this.GetChars(
                new ReadOnlySpan<byte>(bytes, byteCount),
                new Span<char>(chars, charCount),
                write: true);
        }
    }
}
