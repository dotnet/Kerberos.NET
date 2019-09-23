using Kerberos.NET.Crypto;
using System;

namespace Kerberos.NET.Entities
{
    public sealed class NegotiateContextToken : ContextToken
    {
        private readonly NegotiationToken token;

        public NegotiateContextToken(GssApiToken gssToken)
        {
            // SPNego tokens optimistically include a token of the first MechType
            // so if mechType[0] == Ntlm process as ntlm, == kerb process as kerb, etc.

            token = NegotiationToken.Decode(gssToken.Token);
        }

        public override DecryptedKrbApReq DecryptApReq(KeyTable keys)
        {
            var mechToken = token.InitialToken.MechToken;

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
