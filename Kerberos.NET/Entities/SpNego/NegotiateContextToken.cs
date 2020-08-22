// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using Kerberos.NET.Crypto;

namespace Kerberos.NET.Entities
{
    public sealed class NegotiateContextToken : ContextToken
    {
        private readonly NegotiationToken token;

        public NegotiateContextToken(GssApiToken gssToken)
        {
            if (gssToken == null)
            {
                throw new ArgumentNullException(nameof(gssToken));
            }

            // SPNego tokens optimistically include a token of the first MechType
            // so if mechType[0] == Ntlm process as ntlm, == kerb process as kerb, etc.

            this.token = NegotiationToken.Decode(gssToken.Token);
        }

        public override DecryptedKrbApReq DecryptApReq(KeyTable keys)
        {
            var mechToken = this.token.InitialToken.MechToken;

            var apReq = MessageParser.Parse<ContextToken>(mechToken.Value);

            if (apReq is NegotiateContextToken)
            {
                throw new InvalidOperationException(
                    "Negotiated ContextToken is another negotiated token. Failing to prevent stack overflow."
                );
            }

            return apReq.DecryptApReq(keys);
        }
    }
}