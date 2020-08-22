// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

namespace Kerberos.NET.Crypto
{
#if WEAKCRYPTO
    internal sealed class Win32CspMd4 : Win32CspHash
    {
        private const int CALG_MD4 = 0x00008002;
        private const int MD4HashSize = 16;

        public Win32CspMd4()
            : base("MD4", CALG_MD4, MD4HashSize)
        {
        }
    }
#endif
}