using Kerberos.NET.Crypto;
using System.Runtime.InteropServices;
using Kerberos.NET.Asn1;

namespace Kerberos.NET.Entities
{
    public sealed class KerberosContextToken : ContextToken
    {
        public KerberosContextToken(Asn1Element sequence) 
            : base(sequence)
        {
        }

        public KrbApReq KrbApReq;

        public KrbApRep KrbApRep;

        public override DecryptedKrbApReq DecryptApReq(KeyTable keys)
        {
            return DecryptApReq(KrbApReq, keys);
        }

        protected override void ParseApplication(Asn1Element element)
        {
            switch (element.ApplicationTag)
            {
                case KrbApReq.ApplicationTag:
                    KrbApReq = new KrbApReq().Decode(element[0]);
                    break;
                case KrbApRep.ApplicationTag:
                    KrbApRep = new KrbApRep().Decode(element[0]);
                    break;
            }
        }
    }
}
