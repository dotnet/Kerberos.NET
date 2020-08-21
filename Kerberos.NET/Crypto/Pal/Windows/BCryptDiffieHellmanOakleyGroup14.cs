// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;

namespace Kerberos.NET.Crypto
{
    public class BCryptDiffieHellmanOakleyGroup14 : BCryptDiffieHellman
    {
        protected override ReadOnlyMemory<byte> Modulus => Oakley.Group14.Prime;

        protected override ReadOnlyMemory<byte> Generator => Oakley.Group14.Generator;

        protected override ReadOnlyMemory<byte> Factor { get; set; } = Oakley.Group14.Factor;
    }
}