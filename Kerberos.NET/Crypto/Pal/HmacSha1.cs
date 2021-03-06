// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Security.Cryptography;
using static Kerberos.NET.BinaryExtensions;

namespace Kerberos.NET.Crypto
{
    internal class HmacSha1 : HmacAlgorithmBase
    {
        public HmacSha1(ReadOnlyMemory<byte> key)
#pragma warning disable CA5350 // Do Not Use Weak Cryptographic Algorithms
            : base(new HMACSHA1(TryGetArrayFast(key)))
#pragma warning restore CA5350 // Do Not Use Weak Cryptographic Algorithms
        {
        }
    }
}