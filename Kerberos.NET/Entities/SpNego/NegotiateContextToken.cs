// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Linq;
using Kerberos.NET.Crypto;

namespace Kerberos.NET.Entities
{
    public sealed class NegotiateContextToken : ContextToken
    {
        public NegotiateContextToken(GssApiToken gssToken)
            : base(gssToken)
        {
            if (gssToken == null)
            {
                throw new ArgumentNullException(nameof(gssToken));
            }

            // SPNego tokens optimistically include a token of the first MechType
            // so if mechType[0] == Ntlm process as ntlm, == kerb process as kerb, etc.

            this.Token = NegotiationToken.Decode(gssToken.Token);
        }

        public NegotiationToken Token { get; }

        public override DecryptedKrbApReq DecryptApReq(KeyTable keys)
        {
            var mechToken = this.Token.InitialToken.MechToken;

            var apReq = MessageParser.Parse<ContextToken>(mechToken.Value);

            if (apReq is NegotiateContextToken)
            {
                throw new InvalidOperationException(
                    "Negotiated ContextToken is another negotiated token. Failing to prevent stack overflow."
                );
            }

            return apReq.DecryptApReq(keys);
        }

        public override string ToString()
        {
            if (this.Token.InitialToken != null)
            {
                var init = this.Token.InitialToken;
                return $"NegTokenInit Oid: {init.MechTypes?.FirstOrDefault()?.FriendlyName};";
            }

            if (this.Token.ResponseToken != null)
            {
                var resp = this.Token.ResponseToken;

                return $"NegTokenResp Oid: {resp.SupportedMech.FriendlyName};";
            }

            return base.ToString();
        }
    }
}
