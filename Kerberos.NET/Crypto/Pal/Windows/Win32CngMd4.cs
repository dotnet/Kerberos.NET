// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

namespace Kerberos.NET.Crypto
{
#if WEAKCRYPTO
    internal sealed class Win32CngMd4 : Win32CngHash
    {
        private const int MD4HashSize = 16;

        public Win32CngMd4()
            : base("MD4", MD4HashSize)
        {
        }
    }
#endif
}
