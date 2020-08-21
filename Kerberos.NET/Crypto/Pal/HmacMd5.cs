// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Security.Cryptography;
using static Kerberos.NET.BinaryExtensions;

namespace Kerberos.NET.Crypto
{
#if WEAKCRYPTO
    internal class HmacMd5 : IHmacAlgorithm
    {
        public ReadOnlyMemory<byte> ComputeHash(ReadOnlyMemory<byte> key, ReadOnlyMemory<byte> data)
        {
            var keyArray = TryGetArrayFast(key);
            var dataArray = TryGetArrayFast(data);

#pragma warning disable CA5351 // Do Not Use Broken Cryptographic Algorithms
            using (HMACMD5 hmac = new HMACMD5(keyArray))
            {
                return hmac.ComputeHash(dataArray, 0, data.Length);
            }
#pragma warning restore CA5351 // Do Not Use Broken Cryptographic Algorithms
        }
    }
#endif
}