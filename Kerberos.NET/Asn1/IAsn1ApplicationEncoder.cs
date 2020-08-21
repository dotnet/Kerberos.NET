// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;

namespace Kerberos.NET.Asn1
{
    public interface IAsn1ApplicationEncoder<T>
    {
        T DecodeAsApplication(ReadOnlyMemory<byte> data);

        ReadOnlyMemory<byte> EncodeApplication();
    }
}