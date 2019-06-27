﻿using Kerberos.NET.Asn1;
using System.Runtime.InteropServices;

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
        public NegTokenTarg Decode(Asn1Element sequence)
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
                        MechType = new MechType(element[0].AsString());
                        break;
                    case 2:
                        ResponseToken = ContextToken.Parse(element.AsEncapsulatedElement("ResponseToken"));
                        break;
                }
            }

            return this;
        }

        //[ExpectedTag(0)]
        public NegResult Result;// { get; set; }

        //[ExpectedTag(1), OptionalValue]
        public MechType MechType;// { get; set; }

        //[ExpectedTag(2), SequenceOf, OptionalValue]
        public ContextToken ResponseToken;// { get; set; }

        //[ExpectedTag(3), OptionalValue]
        public byte[] MechListMIC;// { get; set; }
    }
}
