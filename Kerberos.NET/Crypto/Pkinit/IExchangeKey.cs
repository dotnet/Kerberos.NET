// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;

namespace Kerberos.NET.Crypto
{
    public interface IExchangeKey
    {
        int KeyLength { get; set; }

        DateTimeOffset? CacheExpiry { get; set; }

        ReadOnlyMemory<byte> PrivateComponent { get; set; }

        ReadOnlyMemory<byte> PublicComponent { get; set; }

        KeyAgreementAlgorithm Algorithm { get; set; }

        AsymmetricKeyType Type { get; set; }

        ReadOnlyMemory<byte> EncodePublicKey();
    }
}