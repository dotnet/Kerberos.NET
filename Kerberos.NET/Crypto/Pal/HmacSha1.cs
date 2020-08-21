// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Security.Cryptography;
using static Kerberos.NET.BinaryExtensions;

namespace Kerberos.NET.Crypto
{
    internal class HmacSha1 : IHmacAlgorithm
    {
        public ReadOnlyMemory<byte> ComputeHash(
            ReadOnlyMemory<byte> key,
            ReadOnlyMemory<byte> data
        )
        {
            var keyArray = TryGetArrayFast(key);
            var dataArray = TryGetArrayFast(data);

#pragma warning disable CA5350 // Do Not Use Weak Cryptographic Algorithms
            using (var hmac = new HMACSHA1(keyArray))
            {
                return hmac.ComputeHash(dataArray, 0, data.Length);
            }
#pragma warning restore CA5350 // Do Not Use Weak Cryptographic Algorithms
        }
    }
}