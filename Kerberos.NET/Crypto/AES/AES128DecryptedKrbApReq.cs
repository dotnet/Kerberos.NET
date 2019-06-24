using Kerberos.NET.Entities;

#pragma warning disable S101 // Types should be named in camel case

namespace Kerberos.NET.Crypto.AES
{
    public class AES128DecryptedKrbApReq : DecryptedKrbApReq
    {
        public AES128DecryptedKrbApReq(KrbApReq token)
            : base(token, new AES128Transformer())
        {
        }
    }
}
