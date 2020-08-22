// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Security.Cryptography;

namespace Kerberos.NET.Crypto
{
#if WEAKCRYPTO
    internal class Md5 : IHashAlgorithm
    {
        public ReadOnlyMemory<byte> ComputeHash(ReadOnlySpan<byte> data)
        {
            var dataArray = data.ToArray();

#pragma warning disable CA5351 // Do Not Use Broken Cryptographic Algorithms
            using (var md5 = MD5.Create())
            {
                return md5.ComputeHash(dataArray);
            }
#pragma warning restore CA5351 // Do Not Use Broken Cryptographic Algorithms
        }

        public void Dispose()
        {
        }
    }
#endif
}