// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using static Kerberos.NET.BinaryExtensions;
using Rfc2898DeriveBytesAlgorithm = System.Security.Cryptography.Rfc2898DeriveBytes;

namespace Kerberos.NET.Crypto
{
    internal class Rfc2898DeriveBytes : IKeyDerivationAlgorithm
    {
        public ReadOnlyMemory<byte> Derive(
            ReadOnlyMemory<byte> passwordBytes,
            ReadOnlyMemory<byte> salt,
            int iterations,
            int keySize
        )
        {
            var passwordArray = TryGetArrayFast(passwordBytes);
            var saltArray = TryGetArrayFast(salt);

#pragma warning disable CA5379 // Do Not Use Weak Key Derivation Function Algorithm
            using (var derive = new Rfc2898DeriveBytesAlgorithm(passwordArray, saltArray, iterations))
            {
                return derive.GetBytes(keySize);
            }
#pragma warning restore CA5379 // Do Not Use Weak Key Derivation Function Algorithm
        }
    }
}