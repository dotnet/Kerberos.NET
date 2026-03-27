// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

namespace Kerberos.NET.Crypto
{
    /// <summary>
    /// Cross-platform managed Diffie-Hellman key agreement using Oakley Group 2 (1024-bit)
    /// per RFC 2409.
    /// </summary>
    public class ManagedDiffieHellmanOakleyGroup2 : ManagedDiffieHellman
    {
        public ManagedDiffieHellmanOakleyGroup2()
            : base(Oakley.Group2.Prime, Oakley.Group2.Generator, Oakley.Group2.Factor)
        {
        }

        public ManagedDiffieHellmanOakleyGroup2(DiffieHellmanKey importKey)
            : base(importKey)
        {
        }
    }
}
