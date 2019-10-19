using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Entities.Pac;
using System;
using System.Collections.Generic;
using System.Diagnostics;
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

        protected virtual ClaimsIdentity ConvertTicket(DecryptedKrbApReq krbApReq)
        {
            var claims = new List<Claim>();
            var restrictions = new List<Restriction>();

            DecodeRestrictions(krbApReq, claims, restrictions);

            SetMinimumIdentity(krbApReq, claims);

            string apRep = null;

            if (krbApReq.Options.HasFlag(ApOptions.MutualRequired))
            {
                var apRepEncoded = krbApReq.CreateResponseMessage().EncodeApplication();

                apRep = Convert.ToBase64String(apRepEncoded.ToArray());
            }

            return new KerberosIdentity(
                claims,
                "Kerberos",
                ClaimTypes.NameIdentifier,
                ClaimTypes.Role,
                restrictions,
                validator.ValidateAfterDecrypt,
                apRep
            );
        }

        private void SetMinimumIdentity(DecryptedKrbApReq krbApReq, List<Claim> claims)
        {
            // there's no guarantee a PAC will be sent along so we should be nice and
            // fill in a minimum set of identifying information like the principal name

            if (claims.Any(c => c.Type == ClaimTypes.Name || c.Type == ClaimTypes.NameIdentifier))
            {
                return;
            }

            claims.Add(new Claim(ClaimTypes.NameIdentifier, krbApReq.Ticket.CName.FullyQualifiedName, ClaimValueTypes.String, AD_AUTHORITY));
        }

        private void DecodeRestrictions(
            DecryptedKrbApReq krbApReq,
            List<Claim> claims,
            List<Restriction> restrictions
        )
        {
            var authenticatorAuthz = krbApReq.Authenticator.AuthorizationData ?? new KrbAuthorizationData[0];
            var ticketAuthz = krbApReq.Ticket.AuthorizationData ?? new KrbAuthorizationData[0];

            var authz = authenticatorAuthz.Concat(ticketAuthz);

            foreach (var authData in authz)
            {
                DecodeAdIfRelevant(krbApReq, claims, authData, restrictions);
            }
        }

        private void DecodeAdIfRelevant(
            DecryptedKrbApReq krbApReq,
            List<Claim> claims,
            KrbAuthorizationData authData,
            List<Restriction> restrictions
        )
        {
            var adif = authData.DecodeAdIfRelevant();

            foreach (var authz in adif)
            {
                switch (authz.Type)
                {
                    case AuthorizationDataType.AdIfRelevant:
                        DecodeAdIfRelevant(krbApReq, claims, authz, restrictions);
                        break;

                    case AuthorizationDataType.AdWin2kPac:
                        DecodePac(krbApReq, claims, authz, restrictions);
                        break;
                    case AuthorizationDataType.AdETypeNegotiation:
                        restrictions.Add(new ETypeNegotiationRestriction(authz));
                        break;
                    case AuthorizationDataType.KerbAuthDataTokenRestrictions:
                        restrictions.Add(new KerbAuthDataTokenRestriction(authz));
                        break;
                    case AuthorizationDataType.KerbApOptions:
                        restrictions.Add(new KerbApOptionsRestriction(authz));
                        break;
                    case AuthorizationDataType.KerbLocal:
                        restrictions.Add(new KerbLocalRestriction(authz));
                        break;
                    case AuthorizationDataType.KerbServiceTarget:
                        restrictions.Add(new KerbServiceTargetRestriction(authz));
                        break;
                    default:
                        Debug.WriteLine($"Unknown authorization-data type {authData.Type} \r\n{authData.Data.DumpHex()}");
                        break;
                }
            }
        }

        private void DecodePac(DecryptedKrbApReq krbApReq, List<Claim> claims, KrbAuthorizationData authz, List<Restriction> restrictions)
        {
            var pac = new PrivilegedAttributeCertificate(authz);

            if (!pac.HasRequiredFields)
            {
                return;
            }

            if (validator.ValidateAfterDecrypt.HasFlag(ValidationActions.Pac))
            {
                ValidatePacSignature(pac, krbApReq.SName);
            }

            MergeAttributes(krbApReq.Ticket, pac, claims);

            restrictions.Add(pac);
        }

        protected virtual void ValidatePacSignature(PrivilegedAttributeCertificate pac, KrbPrincipalName name)
        {
            validator.Validate(pac, name);
        }

        private void MergeAttributes(KrbEncTicketPart ticket, PrivilegedAttributeCertificate pac, List<Claim> claims)
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

        private static void AddClaim(ClaimEntry entry, string issuer, ICollection<Claim> claims)
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

        private const string CERT_AUTHORITY = "CERTIFICATE AUTHORITY";
        private const string AD_AUTHORITY = "AD AUTHORITY";

        private static string GetSourceIssuer(ClaimSourceType source)
        {
            switch (source)
            {
                case ClaimSourceType.CLAIMS_SOURCE_TYPE_CERTIFICATE:
                    return CERT_AUTHORITY;
                case ClaimSourceType.CLAIMS_SOURCE_TYPE_AD:
                default:
                    return AD_AUTHORITY;
            }
        }

        protected virtual void AddUser(KrbEncTicketPart ticket, PrivilegedAttributeCertificate pac, List<Claim> claims)
        {
            var logonInfo = pac.LogonInfo;

            if (logonInfo == null)
            {
                return;
            }

            claims.Add(new Claim(ClaimTypes.Sid, logonInfo.UserSid.Value));

            if (!string.IsNullOrWhiteSpace(logonInfo.UserDisplayName))
            {
                claims.Add(new Claim(ClaimTypes.GivenName, logonInfo.UserDisplayName));
            }

            if (this.UserNameFormat == UserNameFormat.UserPrincipalName)
            {
                var names = ticket.CName.Name.Select(n => $"{n}@{ticket.CRealm.ToLowerInvariant()}");

                claims.AddRange(names.Select(n => new Claim(ClaimTypes.NameIdentifier, n)));
            }
            else
            {
                claims.Add(new Claim(ClaimTypes.NameIdentifier, $"{logonInfo.DomainName}\\{logonInfo.UserName}"));
            }
        }

        protected virtual void AddGroups(PrivilegedAttributeCertificate pac, ICollection<Claim> claims)
        {
            var logonInfo = pac.LogonInfo;

            if (logonInfo == null)
            {
                return;
            }

            var domainSid = logonInfo.DomainSid.Value;

            foreach (var g in logonInfo.GroupSids)
            {
                var sid = g.Value;

                claims.Add(new Claim(ClaimTypes.GroupSid, sid));

                if (sid.StartsWith(domainSid))
                {
                    var friendly = SecurityIdentifierNames.GetFriendlyName(sid, domainSid);

                    if (!sid.Equals(friendly, StringComparison.OrdinalIgnoreCase))
                    {
                        claims.Add(new Claim(ClaimTypes.Role, friendly));
                    }
                }
            }
        }
    }
}
