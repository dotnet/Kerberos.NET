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

        [ExpectedTag(KrbApReq.ApplicationTag), SequenceOf, OptionalValue]
        public KrbApReq KrbApReq;

        [ExpectedTag(KrbApRep.ApplicationTag), SequenceOf, OptionalValue]
        public KrbApRep KrbApRep;

        protected override void ParseApplication(Asn1Element element)
        {
            switch (element.ApplicationTag)
            {
                case KrbApReq.ApplicationTag:
                    KrbApReq = new KrbApReq(element[0]);
                    break;
                case KrbApRep.ApplicationTag:
                    KrbApRep = new KrbApRep(element[0]);
                    break;
            }
        }
    }
}
