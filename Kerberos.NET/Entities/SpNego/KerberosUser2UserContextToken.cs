// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using Kerberos.NET.Crypto;

namespace Kerberos.NET.Entities
{
    public class KerberosUser2UserContextToken : ContextToken
    {
        public KerberosUser2UserContextToken(GssApiToken _)
        {
        }

        public override DecryptedKrbApReq DecryptApReq(KeyTable keys)
        {
            throw new NotSupportedException("Kerberos User to User is not supported");
        }
    }
}