using Kerberos.NET.Crypto;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Kerberos.NET.Entities
{
    public class PrincipalName
    {
        public PrincipalName(Asn1Element element, string realm)
        {
            var childNode = element[0];

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
                        var sb = new StringBuilder();

                        for (int l = 0; l < listNode.Count; l++)
                        {
                            sb.Append(listNode[l].AsString());

                            if (l < listNode.Count - 1)
                            {
                                sb.Append("/");
                            }
                        }

                        Names.Add(sb.ToString());

                        break;
                }
            }

            Realm = realm;
        }

        public PrincipalName(PrincipalNameType nameType, string realm, IEnumerable<string> names)
        {
            NameType = nameType;
            Realm = realm;
            this.names = new List<string>(names);
        }

        public string Realm { get; private set; }

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
