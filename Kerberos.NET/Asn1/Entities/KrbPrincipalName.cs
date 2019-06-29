using System.Diagnostics;
using System.Linq;

namespace Kerberos.NET.Asn1.Entities
{
    [DebuggerDisplay("{Type} {FullyQualifiedName}")]
    public partial struct KrbPrincipalName
    {
        public string FullyQualifiedName => string.Join("/", this.Name);

        public bool Matches(object obj)
        {
            var other = obj as KrbPrincipalName?;

            if (other == null)
            {
                return false;
            }

            // Any NameType is allowed.  Names collection in two objects must contain at least one common name

            var namesIntersected = other.Value.Name.Intersect(Name);

            if (namesIntersected.Count() == 0)
            {
                return false;
            }

            return true;
        }
    }
}
