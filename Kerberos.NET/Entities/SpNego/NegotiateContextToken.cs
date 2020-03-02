using Kerberos.NET.Crypto;
using System;

namespace Kerberos.NET.Entities
{
    public sealed class NegotiateContextToken : ContextToken
    {
        public NegotiateContextToken(GssApiToken gssToken)
        {
            // SPNego tokens optimistically include a token of the first MechType
            // so if mechType[0] == Ntlm process as ntlm, == kerb process as kerb, etc.

            Token = NegotiationToken.Decode(gssToken.Token);
        }

        public NegotiationToken Token { get; }

        public override DecryptedKrbApReq DecryptApReq(KeyTable keys)
        {
            var mechToken = Token.InitialToken.MechToken;

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
