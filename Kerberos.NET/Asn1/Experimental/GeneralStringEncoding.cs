// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System.Text;

namespace System.Security.Cryptography.Asn1
{
    internal class GeneralStringEncoding : UTF8Encoding
    {
        public GeneralStringEncoding(): base(false, throwOnInvalidBytes: true) { }
    }
}