// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using Kerberos.NET.Crypto;

namespace Kerberos.NET.Entities.SpNego
{
    public class NtlmContextToken : ContextToken
    {
        public NtlmContextToken(ReadOnlyMemory<byte> data)
            : base(null)
        {
            this.Token = new NtlmMessage(data);
        }

        public NtlmMessage Token { get; }

        public override DecryptedKrbApReq DecryptApReq(KeyTable keys)
        {
            throw new NotSupportedException("NTLM is not supported");
        }
    }
}
