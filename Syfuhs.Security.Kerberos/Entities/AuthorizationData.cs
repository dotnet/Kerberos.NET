using Syfuhs.Security.Kerberos.Crypto;
using System.Collections.Generic;

namespace Syfuhs.Security.Kerberos.Entities
{
    public class AuthorizationData
    {
        protected AuthorizationData() { }

        public AuthorizationData(Asn1Element element)
        {
            for (var c = 0; c < element.Count; c++)
            {
                var auth = new AuthorizationData();

                for (var i = 0; i < element[c].Count; i++)
                {
                    var child = element[c][i];

                    switch (child.ContextSpecificTag)
                    {
                        case 0:
                            auth.AdType = child.AsLong();
                            break;
                        case 1:
                            auth.Authorizations.Add(new AuthorizationData(child));
                            break;
                        case 128: // this isn't correct and wont ever be reached
                            auth.Authorizations.Add(new PrivilegedAttributeCertificate(child));
                            break;
                        default:
                            auth.AdData = child.Value;
                            break;
                    }
                }

                Authorizations.Add(auth);
            }
        }

        public long AdType { get; private set; }

        public byte[] AdData { get; private set; }

        private List<AuthorizationData> authorizations;

        public List<AuthorizationData> Authorizations { get { return authorizations ?? (authorizations = new List<AuthorizationData>()); } }
    }
}
