using System.Security.Principal;

namespace Syfuhs.Security.Kerberos.Entities.Authorization
{
    public class PacAttribute
    {
        private readonly SecurityIdentifier id;
        private readonly int attributes;

        public PacAttribute(SecurityIdentifier id, int attributes)
        {
            this.id = id;
            this.attributes = attributes;
        }

        public SecurityIdentifier Id { get { return id; } }

        public int Attributes { get { return attributes; } }
    }
}
