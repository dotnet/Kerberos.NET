using Kerberos.NET.Asn1.Entities;
using Kerberos.NET.Entities;

#pragma warning disable S101 // Types should be named in camel case

namespace Kerberos.NET.Crypto.AES
{
    public class AES256DecryptedKrbApReq : DecryptedKrbApReq
    {
        public AES256DecryptedKrbApReq(KrbApReq token)
            : base(token, new AES256Transformer())
        {
        }
    }
}
