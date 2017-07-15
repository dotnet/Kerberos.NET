using Syfuhs.Security.Kerberos.Crypto;
using Syfuhs.Security.Kerberos.Entities;
using Syfuhs.Security.Kerberos.Entities.Authorization;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;

namespace Syfuhs.Security.Kerberos
{
    public class KerberosAuthenticator
    {
        private readonly IKerberosValidator validator;

        public KerberosAuthenticator(KeyTable keytab)
            : this(new KerberosValidator(keytab))
        { }

        public KerberosAuthenticator(IKerberosValidator validator)
        {
            this.validator = validator;
        }

        public virtual ClaimsIdentity Authenticate(string token)
        {
            token = token.Trim();

            // stripping Negotiate or similar schemes if present

            if (token.IndexOf(' ') > 0)
            {
                var split = token.Split(' ');

                token = split[split.Length - 1];
            }

            var tokenBytes = Convert.FromBase64String(token);

            return Authenticate(tokenBytes);
        }

        public virtual ClaimsIdentity Authenticate(byte[] token)
        {
            var data = validator.Validate(token);

            return ConvertTicket(data);
        }

        protected virtual ClaimsIdentity ConvertTicket(DecryptedData data)
        {
            var ticket = data.Ticket;

            var claims = new List<Claim>();

            foreach (var authz in ticket.AuthorizationData.Authorizations)
            {
                if (authz.PrivilegedAttributeCertificate != null)
                {
                    MergeAttributes(ticket, authz.PrivilegedAttributeCertificate, claims);
                }
            }

            return new ClaimsIdentity(claims, "password", ClaimTypes.NameIdentifier, ClaimTypes.Role);
        }

        private static void MergeAttributes(EncTicketPart ticket, PrivilegedAttributeCertificate pac, List<Claim> claims)
        {
            claims.Add(new Claim(ClaimTypes.Sid, pac.LogonInfo.UserSid.Value));

            if (!string.IsNullOrWhiteSpace(pac.LogonInfo.UserDisplayName))
            {
                claims.Add(new Claim(ClaimTypes.GivenName, pac.LogonInfo.UserDisplayName));
            }

            var names = ticket.CName.Names.Select(n => $"{n}@{ticket.CRealm.ToLowerInvariant()}");

            claims.AddRange(names.Select(n => new Claim(ClaimTypes.NameIdentifier, n)));

            var domainSddl = pac.LogonInfo.DomainSid.Value;

            foreach (var g in pac.LogonInfo.GroupSids)
            {
                var sddl = g.Value;

                claims.Add(new Claim(ClaimTypes.GroupSid, sddl));

                if (sddl.StartsWith(domainSddl))
                {
                    var friendly = SecurityIdentifierNames.GetFriendlyName(sddl, domainSddl);

                    if (!sddl.Equals(friendly, StringComparison.OrdinalIgnoreCase))
                    {
                        claims.Add(new Claim(ClaimTypes.Role, friendly));
                    }
                }
            }
        }
    }
}
