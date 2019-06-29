using System.Collections.Generic;
using Kerberos.NET.Asn1;
using System.Linq;
using System.IO;
using Kerberos.NET.Asn1.Entities;

namespace Kerberos.NET.Entities
{
    public class MechToken
    {
        public MechToken Decode(Asn1Element sequence, IEnumerable<MechType> mechTypes)
        {
            var firstMech = mechTypes.FirstOrDefault();

            if (ProcessedAsNegoEx(sequence, firstMech))
            {
                return this;
            }

            sequence = sequence.AsEncapsulatedElement("MechToken");

            if (ProcessedAsNtlm(sequence, firstMech))
            {
                return this;
            }

            ProcessedAsKerberos(sequence, firstMech);

            return this;
        }

        public NegotiateExtension NegotiateExtension;

        public MechType ThisMech;

        public KrbApReq InnerContextToken;

        public NtlmNegotiate NtlmNegotiate;

        private bool ProcessedAsNtlm(Asn1Element sequence, MechType firstMech)
        {
            if (firstMech == null || firstMech.Oid != MechType.NTLM)
            {
                return false;
            }

            DecodeNtlm(sequence);

            return true;
        }

        public MechToken DecodeNtlm(Asn1Element sequence)
        {
            NtlmNegotiate = new NtlmNegotiate(new BinaryReader(new MemoryStream(sequence.Value)));

            return this;
        }

        private void ProcessedAsKerberos(Asn1Element sequence, MechType firstMech)
        {
            for (var i = 0; i < sequence.Count; i++)
            {
                var node = sequence[i];

                switch (node.Class)
                {
                    case LegacyTagClass.Universal:
                        switch (node.UniversalTag)
                        {
                            case UniversalTag.ObjectIdentifier:
                                ThisMech = new MechType(node.AsString());
                                break;
                        }
                        break;
                    case LegacyTagClass.Application:
                        switch (node.ApplicationTag)
                        {
                            case 14:// KrbApReq.ApplicationTag:
                                InnerContextToken = KrbApReq.Decode(node.Value);
                                break;
                        }
                        break;
                }
            }
        }

        private bool ProcessedAsNegoEx(Asn1Element sequence, MechType firstMech)
        {
            if (firstMech == null || firstMech.Oid != MechType.NEGOEX)
            {
                return false;
            }

            NegotiateExtension = new NegotiateExtension(sequence.Value);

            return true;
        }
    }
}
