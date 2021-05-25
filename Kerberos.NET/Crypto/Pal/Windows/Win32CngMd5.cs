// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

namespace Kerberos.NET.Crypto
{
#if WEAKCRYPTO
    internal sealed class Win32CngMd5 : Win32CngHash
    {
        private const int MD5HashSize = 16;

        public Win32CngMd5()
            : base("MD5", MD5HashSize)
        {
        }
    }
#endif
}
