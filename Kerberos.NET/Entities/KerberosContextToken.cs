using Kerberos.NET.Crypto;
using System.Runtime.InteropServices;

namespace Kerberos.NET.Entities
{
    [StructLayout(LayoutKind.Sequential)]
    public sealed class KerberosContextToken : ContextToken
    {
        public KerberosContextToken(Asn1Element sequence) 
            : base(sequence)
        {
        }

        //[ExpectedTag(KrbApReq.ApplicationTag), SequenceOf, OptionalValue]
        public KrbApReq KrbApReq;

        //[ExpectedTag(KrbApRep.ApplicationTag), SequenceOf, OptionalValue]
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
