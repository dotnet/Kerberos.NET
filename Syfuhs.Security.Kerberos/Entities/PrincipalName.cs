using Syfuhs.Security.Kerberos.Crypto;
using System.Collections.Generic;
using System.Linq;

namespace Syfuhs.Security.Kerberos.Entities
{
    public class PrincipalName : Asn1ValueType
    {
        public PrincipalName(Asn1Element element)
        {
            var childNode = element[0];

            Asn1Value = childNode.Value;

            for (var i = 0; i < childNode.Count; i++)
            {
                var node = childNode[i];

                var listNode = node[0];

                switch (node.ContextSpecificTag)
                {
                    case 0:
                        NameType = (PrincipalNameType)listNode.AsLong();
                        break;

                    case 1:
                        for (int l = 0; l < listNode.Count; l++)
                        {
                            Names.Add(listNode[l].AsString());
                        }

                        break;
                }
            }
        }

        private List<string> names;

        public List<string> Names { get { return names ?? (names = new List<string>()); } }

        public PrincipalNameType NameType { get; private set; }

        public override bool Equals(object obj)
        {
            var other = obj as PrincipalName;

            if (other == null)
            {
                return false;
            }

            if (other.NameType != NameType)
            {
                return false;
            }

            var namesIntersected = other.Names.Intersect(Names);

            if (namesIntersected.Count() != other.Names.Count || namesIntersected.Count() != Names.Count)
            {
                return false;
            }

            return true;
        }

        public override int GetHashCode()
        {
            return Names.GetHashCode() ^ NameType.GetHashCode();
        }
    }
}
