// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using Kerberos.NET.Crypto;

namespace Kerberos.NET.Entities
{
    public sealed class KerberosContextToken : ContextToken
    {
        public KerberosContextToken(GssApiToken gssToken = null, ReadOnlyMemory<byte>? data = null)
        {
            var kerb = data ?? gssToken?.Token;

            this.KrbApReq = KrbApReq.DecodeApplication(kerb.Value);
        }

        public KrbApReq KrbApReq { get; set; }

        public KrbApRep KrbApRep { get; set; }

        public override DecryptedKrbApReq DecryptApReq(KeyTable keys)
        {
            return DecryptApReq(this.KrbApReq, keys);
        }
    }
}