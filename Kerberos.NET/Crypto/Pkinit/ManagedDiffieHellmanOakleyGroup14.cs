// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

namespace Kerberos.NET.Crypto
{
    /// <summary>
    /// Cross-platform managed Diffie-Hellman key agreement using Oakley Group 14 (2048-bit)
    /// per RFC 3526 Section 3.
    /// </summary>
    public class ManagedDiffieHellmanOakleyGroup14 : ManagedDiffieHellman
    {
        public ManagedDiffieHellmanOakleyGroup14()
            : base(Oakley.Group14.Prime, Oakley.Group14.Generator, Oakley.Group14.Factor)
        {
        }

        public ManagedDiffieHellmanOakleyGroup14(DiffieHellmanKey importKey)
            : base(importKey)
        {
        }
    }
}
