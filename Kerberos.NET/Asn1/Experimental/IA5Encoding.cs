// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

namespace System.Security.Cryptography.Asn1
{
    internal class IA5Encoding : RestrictedAsciiStringEncoding
    {
        // T-REC-X.680-201508 sec 41, Table 8.
        // ISO International Register of Coded Character Sets to be used with Escape Sequences 001
        //   is ASCII 0x00 - 0x1F
        // ISO International Register of Coded Character Sets to be used with Escape Sequences 006
        //   is ASCII 0x21 - 0x7E
        // Space is ASCII 0x20, delete is ASCII 0x7F.
        //
        // The net result is all of 7-bit ASCII
        internal IA5Encoding()
            : base(0x00, 0x7F)
        {
        }
    }
}
