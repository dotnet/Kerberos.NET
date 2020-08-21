// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace System.Security.Cryptography.Asn1
{
    [ExcludeFromCodeCoverage]
    internal static class AsnCharacterStringEncodings
    {
        private static readonly Text.Encoding Utf8Encoding = new UTF8Encoding(false, throwOnInvalidBytes: true);
        private static readonly Text.Encoding BmpEncoding = new BMPEncoding();
        private static readonly Text.Encoding Ia5Encoding = new IA5Encoding();
        private static readonly Text.Encoding GeneralStringEncoding = new GeneralStringEncoding();
        private static readonly Text.Encoding VisibleStringEncoding = new VisibleStringEncoding();
        private static readonly Text.Encoding NumericStringEncoding = new NumericStringEncoding();
        private static readonly Text.Encoding PrintableStringEncoding = new PrintableStringEncoding();
        private static readonly Text.Encoding T61Encoding = new T61Encoding();

        internal static Text.Encoding GetEncoding(UniversalTagNumber encodingType)
        {
            switch (encodingType)
            {
                case UniversalTagNumber.UTF8String:
                    return Utf8Encoding;
                case UniversalTagNumber.NumericString:
                    return NumericStringEncoding;
                case UniversalTagNumber.PrintableString:
                    return PrintableStringEncoding;
                case UniversalTagNumber.IA5String:
                    return Ia5Encoding;
                case UniversalTagNumber.GeneralString:
                    return GeneralStringEncoding;
                case UniversalTagNumber.VisibleString:
                    return VisibleStringEncoding;
                case UniversalTagNumber.BMPString:
                    return BmpEncoding;
                case UniversalTagNumber.T61String:
                    return T61Encoding;
                default:
                    throw new ArgumentOutOfRangeException(nameof(encodingType), encodingType, null);
            }
        }
    }
}
