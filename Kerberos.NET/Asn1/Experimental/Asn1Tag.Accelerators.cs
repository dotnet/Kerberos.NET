// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

namespace System.Security.Cryptography.Asn1
{
    internal partial struct Asn1Tag
    {
        /// <summary>
        ///   Represents the End-of-Contents meta-tag.
        /// </summary>
        public static readonly Asn1Tag EndOfContents = new(0, (int)UniversalTagNumber.EndOfContents);

        /// <summary>
        ///   Represents the universal class tag for a Boolean value.
        /// </summary>
        public static readonly Asn1Tag Boolean = new(0, (int)UniversalTagNumber.Boolean);

        /// <summary>
        ///   Represents the universal class tag for an Integer value.
        /// </summary>
        public static readonly Asn1Tag Integer = new(0, (int)UniversalTagNumber.Integer);

        /// <summary>
        ///   Represents the universal class tag for a Bit String value under a primitive encoding.
        /// </summary>
        public static readonly Asn1Tag PrimitiveBitString = new(0, (int)UniversalTagNumber.BitString);

        /// <summary>
        ///   Represents the universal class tag for a Bit String value under a constructed encoding.
        /// </summary>
        public static readonly Asn1Tag ConstructedBitString =
            new(ConstructedMask, (int)UniversalTagNumber.BitString);

        /// <summary>
        ///   Represents the universal class tag for an Octet String value under a primitive encoding.
        /// </summary>
        public static readonly Asn1Tag PrimitiveOctetString = new(0, (int)UniversalTagNumber.OctetString);

        /// <summary>
        ///   Represents the universal class tag for a Octet String value under a constructed encoding.
        /// </summary>
        public static readonly Asn1Tag ConstructedOctetString =
            new(ConstructedMask, (int)UniversalTagNumber.OctetString);

        /// <summary>
        ///   Represents the universal class tag for a Null value.
        /// </summary>
        public static readonly Asn1Tag Null = new(0, (int)UniversalTagNumber.Null);

        /// <summary>
        ///   Represents the universal class tag for an Object Identifier value.
        /// </summary>
        public static readonly Asn1Tag ObjectIdentifier = new(0, (int)UniversalTagNumber.ObjectIdentifier);

        /// <summary>
        ///   Represents the universal class tag for an Enumerated value.
        /// </summary>
        public static readonly Asn1Tag Enumerated = new(0, (int)UniversalTagNumber.Enumerated);

        /// <summary>
        ///   Represents the universal class tag for a Sequence value (always a constructed encoding).
        /// </summary>
        public static readonly Asn1Tag Sequence = new(ConstructedMask, (int)UniversalTagNumber.Sequence);

        /// <summary>
        ///   Represents the universal class tag for a SetOf value (always a constructed encoding).
        /// </summary>
        public static readonly Asn1Tag SetOf = new(ConstructedMask, (int)UniversalTagNumber.SetOf);

        /// <summary>
        ///   Represents the universal class tag for a UtcTime value.
        /// </summary>
        public static readonly Asn1Tag UtcTime = new(0, (int)UniversalTagNumber.UtcTime);

        /// <summary>
        ///   Represents the universal class tag for a GeneralizedTime value.
        /// </summary>
        public static readonly Asn1Tag GeneralizedTime = new(0, (int)UniversalTagNumber.GeneralizedTime);
    }
}
