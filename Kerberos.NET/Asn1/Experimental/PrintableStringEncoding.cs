// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

namespace System.Security.Cryptography.Asn1
{
    internal class PrintableStringEncoding : RestrictedAsciiStringEncoding
    {
        // T-REC-X.680-201508 sec 41.4
        internal PrintableStringEncoding()
            : base("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 '()+,-./:=?")
        {
        }
    }
}