// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Security.Cryptography;
using static Kerberos.NET.BinaryExtensions;

namespace Kerberos.NET.Crypto
{
    internal class HmacSha384 : HmacAlgorithmBase
    {
        public HmacSha384(ReadOnlyMemory<byte> key)
            : base (new HMACSHA384(TryGetArrayFast(key)))
        {
        }
    }
}
