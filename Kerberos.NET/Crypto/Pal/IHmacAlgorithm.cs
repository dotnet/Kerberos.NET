// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;

namespace Kerberos.NET.Crypto
{
    public interface IHmacAlgorithm : IDisposable
    {
        int HashSize { get; }
        ReadOnlyMemory<byte> ComputeHash(ReadOnlyMemory<byte> buffer);
    }
}
