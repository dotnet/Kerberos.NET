using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Server;

namespace Kerberos.NET
{
    public class TransitedKerberosPrincipal : IKerberosPrincipal
    {
        private readonly DecryptedKrbApReq clientTicket;

        public TransitedKerberosPrincipal(DecryptedKrbApReq clientTicket)
        {
            this.clientTicket = clientTicket;
        }

        public string PrincipalName => clientTicket.Ticket.CName.FullyQualifiedName;

        public IEnumerable<PaDataType> SupportedPreAuthenticationTypes => Enumerable.Empty<PaDataType>();

        public SupportedEncryptionTypes SupportedEncryptionTypes => 0;

        public PrincipalType Type => PrincipalType.User;

        public DateTimeOffset? Expires => null;

        public PrivilegedAttributeCertificate GeneratePac() => null;

        public KerberosKey RetrieveLongTermCredential()
        {
            throw new NotSupportedException();
        }

        public void Validate(X509Certificate2Collection certificates)
        {
            throw new NotSupportedException();
        }
    }
}
