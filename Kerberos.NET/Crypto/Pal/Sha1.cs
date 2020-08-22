// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Security.Cryptography;

namespace Kerberos.NET.Crypto
{
    internal class Sha1 : IHashAlgorithm
    {
        public ReadOnlyMemory<byte> ComputeHash(ReadOnlySpan<byte> data)
        {
#pragma warning disable CA5350 // Do Not Use Weak Cryptographic Algorithms
            using (var hash = SHA1.Create())
            {
                return hash.ComputeHash(data.ToArray());
            }
#pragma warning restore CA5350 // Do Not Use Weak Cryptographic Algorithms
        }

        public void Dispose()
        {
        }
    }
}