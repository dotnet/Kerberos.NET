﻿using Kerberos.NET.Crypto;
using System;

namespace Kerberos.NET.Entities
{
    public sealed class KerberosContextToken : ContextToken
    {
        public KerberosContextToken(GssApiToken gssToken = null, ReadOnlyMemory<byte>? data = null)
        {
            var kerb = data ?? gssToken?.Token;

            if (KrbApReq.CanDecode(kerb.Value))
            {
                KrbApReq = KrbApReq.DecodeApplication(kerb.Value);
            }
            else if (KrbApRep.CanDecode(kerb.Value))
            {
                KrbApRep = KrbApRep.DecodeApplication(kerb.Value);
            }
        }

        public KrbApReq KrbApReq;

        public KrbApRep KrbApRep;

        public override DecryptedKrbApReq DecryptApReq(KeyTable keys)
        {
            return DecryptApReq(KrbApReq, keys);
        }
    }
}
