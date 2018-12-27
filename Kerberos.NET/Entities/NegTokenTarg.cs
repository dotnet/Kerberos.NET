using Kerberos.NET.Crypto;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Kerberos.NET.Entities
{
    public enum NegResult
    {
        AcceptCompleted = 0,
        AcceptIncomplete = 1,
        Rejected = 2
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct NegTokenTarg
    {
        //public NegTokenTarg() { }

        public void Decode(Asn1Element sequence)
        {
            for (var i = 0; i < sequence.Count; i++)
            {
                var element = sequence[i];

                switch (element.ContextSpecificTag)
                {
                    case 0:
                        Result = (NegResult)element[0].AsInt();
                        break;
                    case 1:
                        MechType = new Oid(element[0].AsString());
                        break;
                    case 2:
                        ResponseToken = ContextToken.Parse(element.AsEncapsulatedElement());
                        break;
                }
            }
        }

        [ExpectedTag(0)]
        public NegResult Result;// { get; set; }

        [ExpectedTag(1), OptionalValue]
        public Oid MechType;// { get; set; }

        [ExpectedTag(2), SequenceOf, OptionalValue]
        public ContextToken ResponseToken;// { get; set; }

        [ExpectedTag(3), OptionalValue]
        public byte[] MechListMIC;// { get; set; }
    }
}
