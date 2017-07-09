using Syfuhs.Security.Kerberos.Crypto;
using System.Collections.Generic;
using System.Diagnostics;

namespace Syfuhs.Security.Kerberos.Entities
{
    [DebuggerDisplay("{AdType}")]
    public class AuthorizationDataElement
    {
        public AuthorizationDataElement(Asn1Element parent)
        {
            for (var i = 0; i < parent.Count; i++)
            {
                var element = parent[i];
                var child = element[0];

                switch (element.ContextSpecificTag)
                {
                    case 0:
                        AdType = child.AsLong();
                        break;
                    case 1:
                        AdData = TryFindPac(new Asn1Element(child.Value));

                        if (AdData != null && AdData.Length > 0)
                        {
                            PrivilegedAttributeCertificate = new PrivilegedAttributeCertificate(AdData);
                        }
                        break;
                }
            }
        }

        private const int AD_WIN2K_PAC = 128;

        private static byte[] TryFindPac(Asn1Element e)
        {
            // e = AD-IF-RELEVANT
            // e[0] = AD-WIN2K-PAC
            // e[0][1] = PACTYPE

            var adWin2kPac = e[0];
            var pacType0 = e[0][0];
            var pacType1 = e[0][1];

            if (pacType0[0].AsInt() == AD_WIN2K_PAC)
            {
                return pacType1[0].Value;
            }

            return null;
        }

        public long AdType { get; private set; }

        public byte[] AdData { get; private set; }
        public PrivilegedAttributeCertificate PrivilegedAttributeCertificate { get; private set; }
    }

    public class AuthorizationData
    {
        protected AuthorizationData() { }

        public AuthorizationData(Asn1Element element)
        {
            for (var c = 0; c < element.Count; c++)
            {
                var child = element[c];

                Authorizations.Add(new AuthorizationDataElement(child));
            }
        }

        private List<AuthorizationDataElement> authorizations;

        public List<AuthorizationDataElement> Authorizations { get { return authorizations ?? (authorizations = new List<AuthorizationDataElement>()); } }
    }
}
