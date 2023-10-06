// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using Kerberos.NET.Crypto;

namespace Kerberos.NET.Entities
{
    public class IAKerbContextToken : ContextToken
    {
        public IAKerbContextToken(GssApiToken gssToken)
            : base(gssToken)
        {
            Memory<byte> body = gssToken.Token.ToArray();

            this.Header = IAKerbHeader.DecodePartial(ref body);
            this.Body = body;
        }

        public IAKerbHeader Header { get; }

        public ReadOnlyMemory<byte> Body { get; }

        public override DecryptedKrbApReq DecryptApReq(KeyTable keys)
            => throw new NotSupportedException();
    }
}
