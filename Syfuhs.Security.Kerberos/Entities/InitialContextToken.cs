using System.Collections.Generic;
using Syfuhs.Security.Kerberos.Crypto;
using System.Linq;

namespace Syfuhs.Security.Kerberos.Entities
{
    public class InitialContextToken
    {
        public InitialContextToken(Asn1Element sequence, IEnumerable<MechType> mechTypes)
        {
            var childNode = new Asn1Element(sequence.Value);

            if (childNode.Count <= 0 && mechTypes.Any(a => a.Oid == MechType.NEGOEX))
            {
                NegotiateExtension = new NegotiateExtension(sequence.Value);
            }

            for (var i = 0; i < childNode.Count; i++)
            {
                var node = childNode[i];

                if (node.ContextSpecificTag == MechType.ContextTag)
                {
                    ThisMech = new MechType(node.AsString());
                }
                else if (node.Count > 0)
                {
                    InnerContextToken = new KrbApReq(node[0]);
                }
            }
        }

        public NegotiateExtension NegotiateExtension { get; private set; }

        public MechType ThisMech { get; private set; }

        public KrbApReq InnerContextToken { get; private set; }
    }
}
