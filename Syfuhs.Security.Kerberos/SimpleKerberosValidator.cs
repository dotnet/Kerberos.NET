using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using Syfuhs.Security.Kerberos.Entities;
using System.Security;

namespace Syfuhs.Security.Kerberos
{
    public class SimpleKerberosValidator
    {
        private static readonly HashSet<string> TokenCache = new HashSet<string>();

        private readonly byte[] key;

        public SimpleKerberosValidator(string key)
            : this(Encoding.Unicode.GetBytes(key))
        { }

        public SimpleKerberosValidator(byte[] key)
        {
            this.key = key;

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

        private ClaimsIdentity Validate(byte[] requestBytes)
        {
            var kerberosRequest = KerberosRequest.Parse(requestBytes);

            Logger(kerberosRequest.ToString());

            var decryptedToken = kerberosRequest.Decrypt(key);

            if (decryptedToken == null)
            {
                return null;
            }

            Logger(decryptedToken.ToString());

            if (ValidateAfterDecrypt)
            {
                Validate(decryptedToken);
            }

            return ConvertTicket(decryptedToken.Ticket);
        }

        private static ClaimsIdentity ConvertTicket(EncTicketPart ticket)
        {
            var names = ticket.CName.Names.Select(n => $"{n}@{ticket.CRealm.ToLowerInvariant()}");

            // TODO: parse authorization data if present and expand PAC data

            return new ClaimsIdentity(names.Select(n => new Claim(ClaimTypes.NameIdentifier, n)), "password");
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
