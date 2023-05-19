// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System.Buffers;
using System.Buffers.Text;
using System.Diagnostics;

namespace System.Security.Cryptography.Asn1
{
    internal sealed partial class AsnWriter
    {
        /*
            NOTE: Implementation divergence

            @omitFractionalSeconds is false in the corefx implementation.

            https://github.com/dotnet/corefx/blob/2ba68b96b53391a04f1b5362fa65bf48c7d8e44e/src/Common/src/System/Security/Cryptography/Asn1/asn.xsd

        */

        /// <summary>
        ///   Write the provided <see cref="DateTimeOffset"/> as a GeneralizedTime with tag
        ///   UNIVERSAL 24, optionally excluding the fractional seconds.
        /// </summary>
        /// <param name="value">The value to write.</param>
        /// <param name="omitFractionalSeconds">
        ///   <c>true</c> to treat the fractional seconds in <paramref name="value"/> as 0 even if
        ///   a non-zero value is present.
        /// </param>
        /// <exception cref="ObjectDisposedException">The writer has been Disposed.</exception>
        /// <seealso cref="WriteGeneralizedTime(Asn1Tag,DateTimeOffset,bool)"/>
        public void WriteGeneralizedTime(DateTimeOffset value, bool omitFractionalSeconds = true)
        {
            this.WriteGeneralizedTimeCore(Asn1Tag.GeneralizedTime, value, omitFractionalSeconds);
        }

        /// <summary>
        ///   Write the provided <see cref="DateTimeOffset"/> as a GeneralizedTime with a specified
        ///   UNIVERSAL 24, optionally excluding the fractional seconds.
        /// </summary>
        /// <param name="tag">The tagto write.</param>
        /// <param name="value">The value to write.</param>
        /// <param name="omitFractionalSeconds">
        ///   <c>true</c> to treat the fractional seconds in <paramref name="value"/> as 0 even if
        ///   a non-zero value is present.
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <paramref name="tag"/>.<see cref="Asn1Tag.TagClass"/> is
        ///   <see cref="TagClass.Universal"/>, but
        ///   <paramref name="tag"/>.<see cref="Asn1Tag.TagValue"/> is not correct for
        ///   the method
        /// </exception>
        /// <exception cref="ObjectDisposedException">The writer has been Disposed.</exception>
        /// <seealso cref="WriteGeneralizedTime(System.Security.Cryptography.Asn1.Asn1Tag,System.DateTimeOffset,bool)"/>
        public void WriteGeneralizedTime(Asn1Tag tag, DateTimeOffset value, bool omitFractionalSeconds = true)
        {
            CheckUniversalTag(tag, UniversalTagNumber.GeneralizedTime);

            // Clear the constructed flag, if present.
            this.WriteGeneralizedTimeCore(tag.AsPrimitive(), value, omitFractionalSeconds);
        }

        // T-REC-X.680-201508 sec 46
        // T-REC-X.690-201508 sec 11.7
        private void WriteGeneralizedTimeCore(Asn1Tag tag, DateTimeOffset value, bool omitFractionalSeconds)
        {
            // GeneralizedTime under BER allows many different options:
            // * (HHmmss), (HHmm), (HH)
            // * "(value).frac", "(value),frac"
            // * frac == 0 may be omitted or emitted
            // non-UTC offset in various formats
            //
            // We're not allowing any of them.
            // Just encode as the CER/DER common restrictions.
            //
            // This results in the following formats:
            // yyyyMMddHHmmssZ
            // yyyyMMddHHmmss.f?Z
            //
            // where "f?" is anything from "f" to "fffffff" (tenth of a second down to 100ns/1-tick)
            // with no trailing zeros.
            DateTimeOffset normalized = value.ToUniversalTime();

            if (normalized.Year > 9999)
            {
                // This is unreachable since DateTimeOffset guards against this internally.
                throw new ArgumentOutOfRangeException(nameof(value));
            }

            // We're only loading in sub-second ticks.
            // Ticks are defined as 1e-7 seconds, so their printed form
            // is at the longest "0.1234567", or 9 bytes.
            Span<byte> fraction = stackalloc byte[0];

            if (!omitFractionalSeconds)
            {
                long floatingTicks = normalized.Ticks % TimeSpan.TicksPerSecond;

                if (floatingTicks != 0)
                {
                    // We're only loading in sub-second ticks.
                    // Ticks are defined as 1e-7 seconds, so their printed form
                    // is at the longest "0.1234567", or 9 bytes.
                    fraction = stackalloc byte[9];

                    decimal decimalTicks = floatingTicks;
                    decimalTicks /= TimeSpan.TicksPerSecond;

                    if (!Utf8Formatter.TryFormat(decimalTicks, fraction, out int bytesWritten, new StandardFormat('G')))
                    {
                        Debug.Fail($"Utf8Formatter.TryFormat could not format {floatingTicks} / TicksPerSecond");
                        throw new CryptographicException();
                    }

                    Debug.Assert(bytesWritten > 2, $"{bytesWritten} should be > 2");
                    Debug.Assert(fraction[0] == (byte)'0');
                    Debug.Assert(fraction[1] == (byte)'.');

                    fraction = fraction.Slice(1, bytesWritten - 1);
                }
            }

            // yyyy, MM, dd, hh, mm, ss
            const int IntegerPortionLength = 4 + 2 + 2 + 2 + 2 + 2;

            // Z, and the optional fraction.
            int totalLength = IntegerPortionLength + 1 + fraction.Length;

            // Because GeneralizedTime is IMPLICIT VisibleString it technically can have
            // a constructed form.
            // DER says character strings must be primitive.
            // CER says character strings <= 1000 encoded bytes must be primitive.
            // So we'll just make BER be primitive, too.
            Debug.Assert(!tag.IsConstructed);
            this.WriteTag(tag);
            this.WriteLength(totalLength);

            int year = normalized.Year;
            int month = normalized.Month;
            int day = normalized.Day;
            int hour = normalized.Hour;
            int minute = normalized.Minute;
            int second = normalized.Second;

            Span<byte> baseSpan = this._buffer.AsSpan(this._offset);
            StandardFormat d4 = new('D', 4);
            StandardFormat d2 = new('D', 2);

            if (!Utf8Formatter.TryFormat(year, baseSpan.Slice(0, 4), out _, d4) ||
                !Utf8Formatter.TryFormat(month, baseSpan.Slice(4, 2), out _, d2) ||
                !Utf8Formatter.TryFormat(day, baseSpan.Slice(6, 2), out _, d2) ||
                !Utf8Formatter.TryFormat(hour, baseSpan.Slice(8, 2), out _, d2) ||
                !Utf8Formatter.TryFormat(minute, baseSpan.Slice(10, 2), out _, d2) ||
                !Utf8Formatter.TryFormat(second, baseSpan.Slice(12, 2), out _, d2))
            {
                Debug.Fail($"Utf8Formatter.TryFormat failed to build components of {normalized:O}");
                throw new CryptographicException();
            }

            this._offset += IntegerPortionLength;
            fraction.CopyTo(baseSpan.Slice(IntegerPortionLength));
            this._offset += fraction.Length;

            this._buffer[this._offset] = (byte)'Z';
            this._offset++;
        }
    }
}
