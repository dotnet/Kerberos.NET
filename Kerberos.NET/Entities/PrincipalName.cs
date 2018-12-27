using Kerberos.NET.Crypto;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Kerberos.NET.Entities
{
    public class PrincipalName
    {
        public PrincipalName() { }

        public PrincipalName Decode(Asn1Element element, string realm)
        {
            for (var i = 0; i < element.Count; i++)
            {
                var node = element[i];

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

            return this;
        }

        public PrincipalName(PrincipalNameType nameType, string realm, IEnumerable<string> names)
        {
            NameType = nameType;
            Realm = realm;
            this.names = new List<string>(names);
        }

        public string Realm;

        private List<string> names;

        public List<string> Names { get { return names ?? (names = new List<string>()); } }

        public PrincipalNameType NameType;

        public override bool Equals(object obj)
        {
            var other = obj as PrincipalName;

            if (other == null)
            {
                return false;
            }

            // NT_PRINCIPAL will not match NT_SRV_INST for example

            if (other.NameType != NameType)
            {
                return false;
            }

            var namesIntersected = other.Names.Intersect(Names);

            // Names list for principal must be exact; additional entries in keytab will fail

            if (namesIntersected.Count() != other.Names.Count || namesIntersected.Count() != Names.Count)
            {
                return false;
            }

            return true;
        }

        public bool Matches(object obj)
        {
            var other = obj as PrincipalName;

            if (other == null)
            {
                return false;
            }

            // Any NameType is allowed.  Names collection in two objects must contain at least one common name

            var namesIntersected = other.Names.Intersect(Names);

            if (namesIntersected.Count() == 0)
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
