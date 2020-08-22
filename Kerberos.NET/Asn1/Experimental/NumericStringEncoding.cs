// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

namespace System.Security.Cryptography.Asn1
{
    internal class NumericStringEncoding : RestrictedAsciiStringEncoding
    {
        // T-REC-X.680-201508 sec 41.2 (Table 9)
        // 0, 1, ... 9 + space
        internal NumericStringEncoding()
            : base("0123456789 ")
        {
        }
    }
}
