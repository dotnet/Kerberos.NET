using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace Kerberos.NET.Entities
{
    [DebuggerDisplay("{NameType} {FullyQualifiedName}@{Realm}")]
    public class PrincipalName
    {
        public PrincipalName() { }

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

        public string FullyQualifiedName => string.Join("/", Names);

        public override bool Equals(object obj)
        {
            if (!(obj is PrincipalName other))
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

        public override int GetHashCode()
        {
            return EntityHashCode.GetHashCode(Names, NameType);
        }
    }
}
