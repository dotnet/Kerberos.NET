// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using Kerberos.NET.Crypto;

namespace Kerberos.NET.Entities.SpNego
{
    public class NegoExContextToken : ContextToken
    {
        public NegoExContextToken(ReadOnlyMemory<byte> data)
        {
            this.Token = new NegotiateExtension(data);
        }

        public NegotiateExtension Token { get; }

        public override DecryptedKrbApReq DecryptApReq(KeyTable keys)
        {
            throw new NotSupportedException("NegoEx is not supported");
        }
    }
}