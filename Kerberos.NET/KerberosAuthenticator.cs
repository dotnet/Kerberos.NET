// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Kerberos.NET.Configuration;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Entities.Pac;
using Microsoft.Extensions.Logging;

namespace Kerberos.NET
{
    public class KerberosAuthenticator
    {
        private const string CERT_AUTHORITY = "CERTIFICATE AUTHORITY";
        private const string AD_AUTHORITY = "AD AUTHORITY";

        private readonly IS4UProvider s4uProvider;
        private readonly IKerberosValidator validator;

        public UserNameFormat UserNameFormat { get; set; } = UserNameFormat.UserPrincipalName;

        public KerberosAuthenticator(string upn, KeyTable keytab, Krb5Config config, ILoggerFactory logger = null)
            : this(new KerberosValidator(keytab, logger))
        {
            if (!string.IsNullOrWhiteSpace(upn))
            {
                this.s4uProvider = new S4UProvider(upn, keytab, config, logger);
            }
        }

        public KerberosAuthenticator(KeyTable keytab, ILoggerFactory logger = null)
            : this(null, keytab, null, logger)
        {

        }

        public KerberosAuthenticator(IKerberosValidator validator)
        {
            this.validator = validator;
        }

        public virtual async Task<ClaimsIdentity> Authenticate(string token)
        {
            token = token?.Trim();

            // stripping Negotiate or similar schemes if present

            if (token.IndexOf(' ') >= 1)
            {
                var split = token.Split(' ');

                token = split[split.Length - 1];
            }

            var tokenBytes = Convert.FromBase64String(token);

            return await this.Authenticate(tokenBytes).ConfigureAwait(false);
        }

        public virtual async Task<ClaimsIdentity> Authenticate(byte[] token)
            => await this.Authenticate((ReadOnlyMemory<byte>)token);

        public virtual async Task<ClaimsIdentity> Authenticate(ReadOnlyMemory<byte> token)
        {
            var data = await this.validator.Validate(token).ConfigureAwait(false);

            return this.ConvertTicket(data);
        }

        protected virtual ClaimsIdentity ConvertTicket(DecryptedKrbApReq krbApReq)
        {
            if (krbApReq == null)
            {
                throw new ArgumentNullException(nameof(krbApReq));
            }

            var claims = new List<Claim>();
            var restrictions = new List<Restriction>();

            this.DecodeRestrictions(krbApReq, claims, restrictions);

            SetMinimumIdentity(krbApReq, claims);

            return new KerberosIdentity(
                new KerberosIdentityResult
                {
                    UserClaims = claims,
                    AuthenticationType = "Kerberos",
                    NameType = ClaimTypes.NameIdentifier,
                    RoleType = ClaimTypes.Role,
                    Restrictions = restrictions,
                    ValidationMode = this.validator.ValidateAfterDecrypt,
                    KrbApReq = krbApReq,
                    S4uProvider = this.s4uProvider
                }
            );
        }

        private static void SetMinimumIdentity(DecryptedKrbApReq krbApReq, List<Claim> claims)
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
            var authenticatorAuthz = krbApReq.Authenticator.AuthorizationData ?? Array.Empty<KrbAuthorizationData>();
            var ticketAuthz = krbApReq.Ticket.AuthorizationData ?? Array.Empty<KrbAuthorizationData>();

            var authz = authenticatorAuthz.Concat(ticketAuthz);

            foreach (var authData in authz)
            {
                this.DecodeAdIfRelevant(krbApReq, claims, authData, restrictions);
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
                        this.DecodeAdIfRelevant(krbApReq, claims, authz, restrictions);
                        break;

                    case AuthorizationDataType.AdWin2kPac:
                        this.DecodePac(krbApReq, claims, authz, restrictions);
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
            var pac = new PrivilegedAttributeCertificate(authz, SignatureMode.Server);

            if (!pac.HasRequiredFields)
            {
                return;
            }

            if (this.validator.ValidateAfterDecrypt.HasFlag(ValidationActions.Pac))
            {
                this.ValidatePacSignature(pac, krbApReq.SName);
            }

            this.MergeAttributes(krbApReq.Ticket, pac, claims);

            restrictions.Add(pac);
        }

        protected virtual void ValidatePacSignature(PrivilegedAttributeCertificate pac, KrbPrincipalName name)
        {
            this.validator.Validate(pac, name);
        }

        private void MergeAttributes(KrbEncTicketPart ticket, PrivilegedAttributeCertificate pac, List<Claim> claims)
        {
            this.AddUser(ticket, pac, claims);

            this.AddGroups(pac, claims);

            var clientClaims = pac?.ClientClaims?.ClaimsSet?.ClaimsArray;

            if (clientClaims != null)
            {
                this.AddClaims(clientClaims, claims);
            }

            var deviceClaims = pac?.DeviceClaims?.ClaimsSet?.ClaimsArray;

            if (deviceClaims != null)
            {
                this.AddClaims(deviceClaims, claims);
            }
        }

        protected virtual void AddClaims(IEnumerable<ClaimsArray> claimsArray, ICollection<Claim> claims)
        {
            if (claimsArray == null)
            {
                throw new ArgumentNullException(nameof(claimsArray));
            }

            if (claims == null)
            {
                throw new ArgumentNullException(nameof(claims));
            }

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
            foreach (var value in entry.GetValuesOfType<string>())
            {
                var claim = new Claim(
                    ExcludeNullTermination(entry.Id),
                    ExcludeNullTermination(value),
                    GetTypeId(entry.Type),
                    issuer
                );

                claims.Add(claim);
            }
        }

        private static string ExcludeNullTermination(string str)
        {
            var index = str.IndexOf('\0');

            if (index > 0)
            {
                return str.Substring(0, index);
            }

            return str;
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
                    return CERT_AUTHORITY;
                case ClaimSourceType.CLAIMS_SOURCE_TYPE_AD:
                default:
                    return AD_AUTHORITY;
            }
        }

        protected virtual void AddUser(KrbEncTicketPart ticket, PrivilegedAttributeCertificate pac, List<Claim> claims)
        {
            if (ticket == null)
            {
                throw new ArgumentNullException(nameof(ticket));
            }

            var logonInfo = pac?.LogonInfo;

            if (logonInfo == null)
            {
                return;
            }

            if (claims == null)
            {
                throw new ArgumentNullException(nameof(claims));
            }

            claims.Add(new Claim(ClaimTypes.Sid, logonInfo.UserSid.Value));

            if (!string.IsNullOrWhiteSpace(logonInfo.UserDisplayName))
            {
                claims.Add(new Claim(ClaimTypes.GivenName, logonInfo.UserDisplayName));
            }

            if (this.UserNameFormat == UserNameFormat.UserPrincipalName)
            {
                if (ticket.CName.FullyQualifiedName.Contains("@"))
                {
                    claims.Add(new Claim(ClaimTypes.NameIdentifier, ticket.CName.FullyQualifiedName));
                }
                else
                {
                    var name = $"{ticket.CName.Name[0]}@{ticket.CRealm.ToLowerInvariant()}";

                    claims.Add(new Claim(ClaimTypes.NameIdentifier, name));
                }
            }
            else
            {
                claims.Add(new Claim(ClaimTypes.NameIdentifier, $"{logonInfo.DomainName.ExcludeTermination()}\\{logonInfo.UserName}"));
            }
        }

        protected virtual void AddGroups(PrivilegedAttributeCertificate pac, ICollection<Claim> claims)
        {
            var logonInfo = pac?.LogonInfo;

            if (logonInfo == null)
            {
                return;
            }

            if (claims == null)
            {
                throw new ArgumentNullException(nameof(claims));
            }

            if (pac?.CredentialType != null)
            {
                claims.Add(new Claim(ClaimTypes.GroupSid, "S-1-5-65-1"));
            }

            var domainSid = logonInfo.DomainSid.Value;

            AddSids(claims, domainSid, logonInfo.GroupSids);

            if (logonInfo.UserFlags.HasFlag(UserFlags.LOGON_EXTRA_SIDS))
            {
                AddSids(claims, domainSid, logonInfo.ExtraSids);
            }

            if (logonInfo.UserFlags.HasFlag(UserFlags.LOGON_RESOURCE_GROUPS))
            {
                AddSids(claims, domainSid, logonInfo.ResourceGroups);
            }
        }

        private static void AddSids(ICollection<Claim> claims, string domainSid, IEnumerable<SecurityIdentifier> sids)
        {
            foreach (var g in sids)
            {
                var sid = g.Value;

                claims.Add(new Claim(ClaimTypes.GroupSid, sid));

                if (sid.StartsWith(domainSid, StringComparison.OrdinalIgnoreCase))
                {
                    var friendly = SecurityIdentifierNames.GetFriendlyName(sid, domainSid);

                    if (!string.IsNullOrWhiteSpace(friendly))
                    {
                        claims.Add(new Claim(ClaimTypes.Role, friendly));
                    }
                }
            }
        }
    }
}
