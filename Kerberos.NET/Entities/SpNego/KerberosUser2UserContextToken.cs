using System;
using Kerberos.NET.Crypto;

namespace Kerberos.NET.Entities
{
    public class KerberosUser2UserContextToken : ContextToken
    {
        public KerberosUser2UserContextToken(GssApiToken? _)
        {

        }

        public override DecryptedKrbApReq DecryptApReq(KeyTable keys)
        {
            throw new NotSupportedException("Kerberos User to User is not supported");
        }
    }
}
