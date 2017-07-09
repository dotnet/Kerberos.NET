using System;
using System.Linq;
using System.Security.Claims;
using Syfuhs.Security.Kerberos.Entities;
using System.Security;
using Syfuhs.Security.Kerberos.Crypto;
using System.Collections.Generic;

namespace Syfuhs.Security.Kerberos
{
    public class SimpleKerberosValidator
    {
        private readonly ITicketCacheValidator TokenCache;

        private readonly KerberosKey key;

        public SimpleKerberosValidator(byte[] key, ITicketCacheValidator ticketCache = null)
            : this(new KerberosKey(key), ticketCache)
        { }


        public SimpleKerberosValidator(KerberosKey key, ITicketCacheValidator ticketCache = null)
        {
            this.key = key;

            TokenCache = ticketCache ?? new SimpleTicketCacheValidator();

            ValidateAfterDecrypt = true;
        }

        public Action<string> Logger = (s) => { };

        public bool ValidateAfterDecrypt { get; set; }

        public virtual ClaimsIdentity Validate(string request)
        {
            request = request.Trim(); // stripping Negotiate 

            if (request.IndexOf(' ') > 0)
            {
                var split = request.Split(' ');

                request = split[split.Length - 1];
            }

            var requestBytes = Convert.FromBase64String(request);

            return Validate(requestBytes);
        }

        public ClaimsIdentity Validate(byte[] requestBytes)
        {
            var kerberosRequest = KerberosRequest.Parse(requestBytes);

            Logger("Request: ");
            Logger(kerberosRequest.ToString());

            var decryptedToken = kerberosRequest.Decrypt(key);

            if (decryptedToken == null)
            {
                return null;
            }

            Logger("\r\n");
            Logger("Ticket: ");
            Logger(decryptedToken.ToString());

            if (ValidateAfterDecrypt)
            {
                Validate(decryptedToken);
            }

            return ConvertTicket(decryptedToken.Ticket);
        }

        private static ClaimsIdentity ConvertTicket(EncTicketPart ticket)
        {
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
            claims.Add(new Claim(ClaimTypes.GivenName, pac.LogonInfo.UserDisplayName));

            var names = ticket.CName.Names.Select(n => $"{n}@{ticket.CRealm.ToLowerInvariant()}");
            claims.AddRange(names.Select(n => new Claim(ClaimTypes.NameIdentifier, n)));

            foreach (var g in pac.LogonInfo.GroupSids)
            {
                claims.Add(new Claim(ClaimTypes.GroupSid, g.Value));
            }
        }

        protected virtual void Validate(DecryptedData decryptedToken)
        {
            decryptedToken.Validate();

            var ctime = decryptedToken.Authenticator.CTime.ToFileTime();
            var cusec = decryptedToken.Authenticator.CuSec;
            var cname = decryptedToken.Authenticator.CName.GetHashCode();
            var crealm = decryptedToken.Authenticator.Realm;

            var ticketIdentifier = $"{ctime}${cusec}${cname}${crealm}";

            if (!TokenCache.Add(ticketIdentifier))
            {
                throw new SecurityException($"Tickets can only be used once. This ticket has already been used: {ticketIdentifier}");
            }
        }
    }
}
