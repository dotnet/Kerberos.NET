// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;

namespace Kerberos.NET.Crypto
{
    public interface ISymmetricAlgorithm
    {
        Memory<byte> Encrypt(
            ReadOnlyMemory<byte> data,
            ReadOnlyMemory<byte> key,
            ReadOnlyMemory<byte> iv
        );

        Memory<byte> Decrypt(
            ReadOnlyMemory<byte> data,
            ReadOnlyMemory<byte> key,
            ReadOnlyMemory<byte> iv
        );
    }
}
