using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Entities.Authorization;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Kerberos.NET
{
    public class KerberosAuthenticator
    {
        private readonly IKerberosValidator validator;

        public UserNameFormat UserNameFormat { get; set; } = UserNameFormat.UserPrincipalName;

        public KerberosAuthenticator(KeyTable keytab)
            : this(new KerberosValidator(keytab))
        { }

        public KerberosAuthenticator(IKerberosValidator validator)
        {
            this.validator = validator;
        }

        public virtual async Task<ClaimsIdentity> Authenticate(string token)
        {
            token = token.Trim();

            // stripping Negotiate or similar schemes if present

            if (token.IndexOf(' ') >= 1)
            {
                var split = token.Split(' ');

                token = split[split.Length - 1];
            }

            var tokenBytes = Convert.FromBase64String(token);

            return await Authenticate(tokenBytes);
        }

        public virtual async Task<ClaimsIdentity> Authenticate(byte[] token)
        {
            var data = await validator.Validate(token);

            return ConvertTicket(data);
        }

        protected virtual ClaimsIdentity ConvertTicket(DecryptedKrbApReq data)
        {
            var ticket = data.Ticket;

            var claims = new List<Claim>();

            foreach (var authData in ticket.AuthorizationData)
            {
                foreach (var authz in authData.Authorizations)
                {
                    if (authz.Type == AuthorizationDataValueType.AD_WIN2K_PAC)
                    {
                        var pac = (PacElement)authz;

                        if (validator.ValidateAfterDecrypt.HasFlag(ValidationActions.Pac))
                        {
                            ValidatePacSignature(pac, data.SName);
                        }

                        MergeAttributes(ticket, pac.Certificate, claims);
                    }
                }
            }

            claims.Add(new Claim("Validated", validator.ValidateAfterDecrypt.ToString().Replace(", ", " ")));

            return new ClaimsIdentity(claims, "Kerberos", ClaimTypes.NameIdentifier, ClaimTypes.Role);
        }

        protected virtual void ValidatePacSignature(PacElement pac, PrincipalName name)
        {
            validator.Validate(pac, name);
        }

        private void MergeAttributes(EncTicketPart ticket, PrivilegedAttributeCertificate pac, List<Claim> claims)
        {
            AddUser(ticket, pac, claims);

            AddGroups(pac, claims);

            var clientClaims = pac?.ClientClaims?.ClaimsSet?.ClaimsArray;

            if (clientClaims != null)
            {
                AddClaims(clientClaims, claims);
            }

            var deviceClaims = pac?.DeviceClaims?.ClaimsSet?.ClaimsArray;

            if (deviceClaims != null)
            {
                AddClaims(deviceClaims, claims);
            }
        }

        protected virtual void AddClaims(IEnumerable<ClaimsArray> claimsArray, ICollection<Claim> claims)
        {
            foreach (var array in claimsArray)
            {
                var issuer = GetSourceIssuer(array.ClaimSource);

                foreach (var entry in array.ClaimEntries)
                {
                    AddClaim(entry, issuer, claims);
                }
            }
        }

        private void AddClaim(ClaimEntry entry, string issuer, ICollection<Claim> claims)
        {
            foreach (var value in entry.GetValues<string>())
            {
                var claim = new Claim(entry.Id, value, GetTypeId(entry.Type), issuer);

                claims.Add(claim);
            }
        }

        private static string GetTypeId(ClaimType type)
        {
            switch (type)
            {
                case ClaimType.CLAIM_TYPE_BOOLEAN:
                    return ClaimValueTypes.Boolean;
                case ClaimType.CLAIM_TYPE_INT64:
                    return ClaimValueTypes.Integer64;
                case ClaimType.CLAIM_TYPE_UINT64:
                    return ClaimValueTypes.UInteger64;
                case ClaimType.CLAIM_TYPE_STRING:
                default:
                    return ClaimValueTypes.String;
            }
        }

        private static string GetSourceIssuer(ClaimSourceType source)
        {
            switch (source)
            {
                case ClaimSourceType.CLAIMS_SOURCE_TYPE_CERTIFICATE:
                    return "CERTIFICATE AUTHORITY";
                case ClaimSourceType.CLAIMS_SOURCE_TYPE_AD:
                default:
                    return "AD AUTHORITY";
            }
        }

        protected virtual void AddUser(EncTicketPart ticket, PrivilegedAttributeCertificate pac, List<Claim> claims)
        {
            claims.Add(new Claim(ClaimTypes.Sid, pac.LogonInfo.UserSid.Value));

            if (!string.IsNullOrWhiteSpace(pac.LogonInfo.UserDisplayName))
            {
                claims.Add(new Claim(ClaimTypes.GivenName, pac.LogonInfo.UserDisplayName));
            }

            if (this.UserNameFormat == UserNameFormat.UserPrincipalName)
            {
                var names = ticket.CName.Names.Select(n => $"{n}@{ticket.CRealm.ToLowerInvariant()}");

                claims.AddRange(names.Select(n => new Claim(ClaimTypes.NameIdentifier, n)));
            }
            else
            {
                claims.Add(new Claim(ClaimTypes.NameIdentifier, $"{pac.LogonInfo.DomainName}\\{pac.LogonInfo.UserName}"));
            }
        }



        protected virtual void AddGroups(PrivilegedAttributeCertificate pac, ICollection<Claim> claims)
        {
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
