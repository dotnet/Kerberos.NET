// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Server;

namespace Kerberos.NET
{
    public class TransitedKerberosPrincipal : IKerberosPrincipal
    {
        private readonly DecryptedKrbApReq clientTicket;
        private readonly PrivilegedAttributeCertificate pac;

        public TransitedKerberosPrincipal(DecryptedKrbApReq clientTicket)
        {
            this.clientTicket = clientTicket;
            this.pac = DecodePac(clientTicket);
        }

        private static PrivilegedAttributeCertificate DecodePac(DecryptedKrbApReq req)
        {
            var authEx = new KerberosAuthenticatorEx();

            return authEx.ParsePac(req);
        }

        public string PrincipalName => this.clientTicket.Ticket.CName.FullyQualifiedName;

        public IEnumerable<PaDataType> SupportedPreAuthenticationTypes => Enumerable.Empty<PaDataType>();

        public SupportedEncryptionTypes SupportedEncryptionTypes => 0;

        public PrincipalType Type => PrincipalType.User;

        public DateTimeOffset? Expires => null;

        public PrivilegedAttributeCertificate GeneratePac() => this.pac;

        public KerberosKey RetrieveLongTermCredential()
        {
            throw new NotSupportedException();
        }

        public KerberosKey RetrieveLongTermCredential(EncryptionType type)
        {
            throw new NotSupportedException();
        }

        public void Validate(X509Certificate2Collection certificates)
        {
            throw new NotSupportedException();
        }

        private class KerberosAuthenticatorEx : KerberosAuthenticator
        {
            public KerberosAuthenticatorEx() : base(new ValidatorEx())
            {
            }

            public PrivilegedAttributeCertificate ParsePac(DecryptedKrbApReq req)
            {
                var claims = new List<Claim>();
                var restrictions = new List<Restriction>();

                DecodeRestrictions(req, claims, restrictions);

                return restrictions.OfType<PrivilegedAttributeCertificate>().FirstOrDefault();
            }

            private class ValidatorEx : IKerberosValidator
            {
                public ValidationActions ValidateAfterDecrypt
                {
                    get => ValidationActions.None;
                    set => throw new NotImplementedException();
                }

                public Task<DecryptedKrbApReq> Validate(byte[] requestBytes) => throw new NotImplementedException();
                public Task<DecryptedKrbApReq> Validate(ReadOnlyMemory<byte> requestBytes) => throw new NotImplementedException();
                public void Validate(PrivilegedAttributeCertificate pac, KrbPrincipalName sname) => throw new NotImplementedException();
            }
        }
    }
}
