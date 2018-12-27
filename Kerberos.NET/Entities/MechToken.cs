using System.Collections.Generic;
using Kerberos.NET.Crypto;
using System.Linq;

namespace Kerberos.NET.Entities
{
    public class MechToken
    {
        public MechToken Decode(Asn1Element sequence, IEnumerable<MechType> mechTypes)
        {
            if (sequence.Count <= 0 && mechTypes.Any(a => a.Oid == MechType.NEGOEX))
            {
                NegotiateExtension = new NegotiateExtension(sequence.Value);
            }

            for (var i = 0; i < sequence.Count; i++)
            {
                var node = sequence[i];

                switch (node.Class)
                {
                    case TagClass.Universal:
                        switch (node.UniversalTag)
                        {
                            case 0:
                                break;
                            case 1:
                                break;
                            case MechType.UniversalTag:
                                ThisMech = new MechType(node.AsString());
                                break;
                        }
                        break;
                    case TagClass.Application:
                        switch (node.ApplicationTag)
                        {
                            case KrbApReq.ApplicationTag:
                                InnerContextToken = new KrbApReq().Decode(node[0]);
                                break;
                        }
                        break;
                }
            }

            return this;
        }

        public NegotiateExtension NegotiateExtension;

        public MechType ThisMech;

        public KrbApReq InnerContextToken;
    }
}
