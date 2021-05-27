// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Security.Cryptography;

namespace Kerberos.NET.Crypto
{
    public interface IKeyDerivationAlgorithm
    {
        ReadOnlyMemory<byte> Derive(
            HashAlgorithmName algName,
            ReadOnlyMemory<byte> passwordBytes,
            ReadOnlyMemory<byte> salt,
            int k,
            int keySize
        );
    }
}