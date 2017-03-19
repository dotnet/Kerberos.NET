using Syfuhs.Security.Kerberos.Crypto;

namespace Syfuhs.Security.Kerberos.Entities
{
    public class InitialContextToken : Asn1ValueType
    {
        public InitialContextToken(Asn1Element sequence)
        {
            var childNode = new Asn1Element(sequence[0].Value);

            Asn1Value = childNode.Value;

            for (var i = 0; i < childNode.Count; i++)
            {
                var node = childNode[i];

                if (node.ContextSpecificTag == MechType.ContextTag)
                {
                    ThisMech = new MechType(node.AsString());
                }
                else if (node.Count > 0)
                {
                    InnerContextToken = new KrbApReq(node);
                }
            }
        }

        public MechType ThisMech { get; private set; }

        public KrbApReq InnerContextToken { get; private set; }
    }
}
