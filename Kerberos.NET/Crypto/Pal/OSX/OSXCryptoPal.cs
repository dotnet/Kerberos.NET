// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

namespace Kerberos.NET.Crypto
{
    public class OSXCryptoPal : LinuxCryptoPal
    {
        public OSXCryptoPal()
        {
            if (!IsOsX)
            {
                throw PlatformNotSupported();
            }
        }
    }
}
