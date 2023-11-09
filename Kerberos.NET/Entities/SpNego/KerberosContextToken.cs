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
            : base(gssToken)
        {
            var kerb = data ?? gssToken?.Token;

            if (!KrbApChoice.CanDecode(kerb.Value, out MessageType type))
            {
                throw new KerberosProtocolException();
            }

            if (type == MessageType.KRB_AP_REQ)
            {
                this.KrbApReq = KrbApReq.DecodeApplication(kerb.Value);
            }
            else if (type == MessageType.KRB_AS_REP)
            {
                this.KrbApRep = KrbApRep.DecodeApplication(kerb.Value);
            }
        }

        public KrbApReq KrbApReq { get; set; }

        public KrbApRep KrbApRep { get; set; }

        public override DecryptedKrbApReq DecryptApReq(KeyTable keys)
            => DecryptApReq(this.KrbApReq, keys);

        public override string ToString()
        {
            if (this.KrbApReq != null)
            {
                var ap = this.KrbApReq;

                return $"{ap.Ticket.SName.FullyQualifiedName}@{ap.Ticket.Realm}";
            }

            if (this.KrbApRep != null)
            {
                return this.KrbApRep.ToString();
            }

            return base.ToString();
        }
    }
}
