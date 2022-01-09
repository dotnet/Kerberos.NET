// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Kerberos.NET.Client;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;

namespace Kerberos.NET
{
    internal sealed class KerberosIdentityResult
    {
        public IEnumerable<Claim> UserClaims { get; set; }

        public string AuthenticationType { get; set; }

        public string NameType { get; set; }

        public string RoleType { get; set; }

        public IEnumerable<Restriction> Restrictions { get; set; }

        public ValidationActions ValidationMode { get; set; }

        public DecryptedKrbApReq KrbApReq { get; set; }

        public IS4UProvider S4uProvider { get; set; }
    }

    public class KerberosIdentity : ClaimsIdentity
    {
        private readonly IS4UProvider s4uProvider;
        private readonly DecryptedKrbApReq krbApReq;

        internal KerberosIdentity(KerberosIdentityResult identity)
            : base(identity.UserClaims, identity.AuthenticationType, identity.NameType, identity.RoleType)
        {
            this.Restrictions = identity.Restrictions.GroupBy(r => r.Type).ToDictionary(r => r.Key, r => r.ToList().AsEnumerable());
            this.ValidationMode = identity.ValidationMode;

            if (identity.KrbApReq.Options.HasFlag(ApOptions.MutualRequired))
            {
                var apRepEncoded = identity.KrbApReq.CreateResponseMessage().EncodeApplication();

                this.ApRep = Convert.ToBase64String(apRepEncoded.ToArray());
            }

            this.SessionKey = identity.KrbApReq.SessionKey.GetKey();
            this.s4uProvider = identity.S4uProvider;
            this.krbApReq = identity.KrbApReq;
        }

        public IDictionary<AuthorizationDataType, IEnumerable<Restriction>> Restrictions { get; }

        public ValidationActions ValidationMode { get; }

        public ReadOnlyMemory<byte> SessionKey { get; }

        public string ApRep { get; }


        /// <summary>
        /// Request a service ticket from a KDC using TGS-REQ
        /// </summary>
        /// <param name="spn">The SPN of the requested service</param>
        /// <returns>Returns the requested <see cref="ApplicationSessionContext"/></returns>
        public async Task<ApplicationSessionContext> GetDelegatedServiceTicket(string spn)
        {
            return await this.GetDelegatedServiceTicket(new RequestServiceTicket { ServicePrincipalName = spn }).ConfigureAwait(false);
        }

        /// <summary>
        /// Request a service ticket from a KDC using TGS-REQ
        /// </summary>
        /// <param name="rst">The parameters of the request</param>
        /// <param name="cancellation">A cancellation token to exit the request early</param>
        /// <returns>Returns a <see cref="ApplicationSessionContext"/> containing the service ticket</returns>
        public async Task<ApplicationSessionContext> GetDelegatedServiceTicket(
            RequestServiceTicket rst,
            CancellationToken cancellation = default
        )
        {
            if (this.s4uProvider == null)
            {
                throw new InvalidOperationException("S4U is not configured for this identity");
            }

            //rst.S4uTarget = rst.ServicePrincipalName;
            rst.S4uTicket = this.krbApReq.EncryptedTicket;
            rst.KdcOptions |= KdcOptions.CNameInAdditionalTicket;

            return await this.s4uProvider.GetServiceTicket(rst, cancellation);
        }
    }
}
