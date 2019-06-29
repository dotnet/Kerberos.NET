using Kerberos.NET.Crypto;
using System.Runtime.InteropServices;
using Kerberos.NET.Asn1;
using Kerberos.NET.Asn1.Entities;

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
                case 14: // KrbApReqLegacy.ApplicationTag:
                    KrbApReq = KrbApReq.Decode(element.Value);
                    break;
                case 15: // KrbApRep.ApplicationTag:
                    KrbApRep = KrbApRep.Decode(element.Value);
                    break;
            }
        }
    }
}
