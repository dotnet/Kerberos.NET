using Kerberos.NET.Crypto;

namespace Kerberos.NET.Entities
{
    public sealed class KerberosContextToken : ContextToken
    {
        public KerberosContextToken(GssApiToken gssToken = null, byte[] data = null)
        {
            var kerb = data ?? gssToken?.Field2;

            var choice = KrbApChoice.Decode(kerb.Value);

            if (choice.ApReq != null)
            {
                KrbApReq = choice.ApReq;
            }

            if (choice.ApRep != null)
            {
                KrbApRep = choice.ApRep;
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
