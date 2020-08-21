// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

namespace System.Security.Cryptography.Asn1
{
    internal class VisibleStringEncoding : RestrictedAsciiStringEncoding
    {
        // T-REC-X.680-201508 sec 41, Table 8.
        // ISO International Register of Coded Character Sets to be used with Escape Sequences 006
        //   is ASCII 0x21 - 0x7E
        // Space is ASCII 0x20.
        internal VisibleStringEncoding()
            : base(0x20, 0x7E)
        {
        }
    }
}
