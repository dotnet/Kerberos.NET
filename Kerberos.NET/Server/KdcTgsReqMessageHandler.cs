// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Microsoft.Extensions.Logging;
using static Kerberos.NET.Entities.KerberosConstants;

namespace Kerberos.NET.Server
{
    public class KdcTgsReqMessageHandler : KdcMessageHandlerBase
    {
        // the logic for a TGS-REQ is relatively simple in the primary case where you have a TGT and want
        // to get a ticket to another service. It gets a bit more complicated when you need to do something
        // like a U2U exchange, renew, or get a referral to another realm.
        //
        // This process is split into two logical steps
        //
        // 1. Validate and authenticate the request
        // 2. Find and issue a service ticket for the user

        private static readonly IEnumerable<PaDataType> ExpectedPreAuthTypes = new[] { PaDataType.PA_TGS_REQ };

        private readonly ILogger<KdcTgsReqMessageHandler> logger;

        public KdcTgsReqMessageHandler(ReadOnlyMemory<byte> message, KdcServerOptions options)
            : base(message, options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            this.logger = options.Log.CreateLoggerSafe<KdcTgsReqMessageHandler>();

            this.PreAuthHandlers[PaDataType.PA_TGS_REQ] = service => new PaDataTgsTicketHandler(service);
        }

        protected override IKerberosMessage DecodeMessageCore(ReadOnlyMemory<byte> message)
        {
            var tgsReq = KrbTgsReq.DecodeApplication(message);

            this.SetRealmContext(tgsReq.Realm);

            return tgsReq;
        }

        protected override MessageType MessageType => MessageType.KRB_TGS_REQ;

        protected override IEnumerable<PaDataType> GetOrderedPreAuth(PreAuthenticationContext preauth) => ExpectedPreAuthTypes;

        public override void QueryPreValidate(PreAuthenticationContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context.EvidenceTicketIdentity != null)
            {
                return;
            }

            var apReq = PaDataTgsTicketHandler.ExtractApReq(context);

            context.EvidenceTicketIdentity = this.RealmService.Principals.Find(apReq.Ticket.SName, apReq.Ticket.Realm);
        }

        public override async Task QueryPreValidateAsync(PreAuthenticationContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context.EvidenceTicketIdentity != null)
            {
                return;
            }

            var apReq = PaDataTgsTicketHandler.ExtractApReq(context);

            context.EvidenceTicketIdentity = await this.RealmService.Principals.FindAsync(apReq.Ticket.SName).ConfigureAwait(false);
        }

        public override void ValidateTicketRequest(PreAuthenticationContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            this.ProcessPreAuth(context);

            if (!context.PreAuthenticationSatisfied)
            {
                throw new KerberosProtocolException(KerberosErrorCode.KDC_ERR_PADATA_TYPE_NOSUPP);
            }

            if (context.Principal == null)
            {
                context.Principal = this.TransformClientIdentity(context);
            }

            // this should never hit since we just copy the principal information from the krbtgt
            // but callers can override TransformClientIdentity so lets fail quickly to be safe

            if (context.Principal == null)
            {
                throw new KerberosProtocolException(KerberosErrorCode.KDC_ERR_C_PRINCIPAL_UNKNOWN);
            }
        }

        protected virtual IKerberosPrincipal TransformClientIdentity(PreAuthenticationContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            var state = context.GetState<TgsState>(PaDataType.PA_TGS_REQ);

            if (state.DecryptedApReq == null)
            {
                throw new KerberosProtocolException(KerberosErrorCode.KDC_ERR_BADOPTION);
            }

            // now that we have the identity from the ticket we duplicate all its interesting bits
            // to include in the requested service ticket but excluding any potentially dangerous
            // authz values if it's from a referred realm

            if (context.EvidenceTicketIdentity.Type == PrincipalType.TrustedDomain)
            {
                // it's a referral from another realm so all the copy and filter
                // goop is in TransitedKerberosPrincipal.GeneratePac()

                return new TransitedKerberosPrincipal(state.DecryptedApReq);
            }

            // TODO: shouldn't be calling Find(), but instead copying the existing PAC
            // This won't need an async call because it'll eventually go away

            return this.RealmService.Principals.Find(state.DecryptedApReq.Ticket.CName, state.DecryptedApReq.Ticket.CRealm);
        }

        public override void QueryPreExecute(PreAuthenticationContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            var tgsReq = (KrbTgsReq)context.Message;

            this.logger.LogInformation(
                "TGS-REQ incoming. SPN = {SPN}, Realm {REALM}",
                tgsReq.Body.SName.FullyQualifiedName,
                tgsReq.Body.Realm);

            context.ServicePrincipal = this.RealmService.Principals.Find(tgsReq.Body.SName, tgsReq.Body.Realm);
        }

        public override async Task QueryPreExecuteAsync(PreAuthenticationContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            var tgsReq = (KrbTgsReq)context.Message;

            this.logger.LogInformation(
                "TGS-REQ incoming. SPN = {SPN}, Realm {REALM}",
                tgsReq.Body.SName.FullyQualifiedName,
                tgsReq.Body.Realm);

            context.ServicePrincipal = await this.RealmService.Principals.FindAsync(tgsReq.Body.SName, tgsReq.Body.Realm).ConfigureAwait(false);
        }

        public override ReadOnlyMemory<byte> ExecuteCore(PreAuthenticationContext context)
        {
            // Now that we know who is requesting the ticket we can issue the ticket
            //
            // 3. Find the requested service principal
            // 4. Determine if the requested service principal is in another realm and if so refer them
            // 5. Evaluate whether the client identity should get a ticket to the service
            // 6. Evaluate whether it should do U2U and if so extract that key instead
            // 7. Generate a service ticket for the calling client to the service
            // 8. return to client

            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            var tgsReq = (KrbTgsReq)context.Message;

            if (context.ServicePrincipal == null)
            {
                // we can't find what they're asking for, but maybe it's in a realm we can transit?

                context.ServicePrincipal = this.ProposeTransitedRealm(tgsReq, context);
            }

            if (context.ServicePrincipal == null)
            {
                // we have no idea what service they're asking for and
                // there isn't a realm we can refer them to that can issue a ticket

                return GenerateError(
                    KerberosErrorCode.KDC_ERR_S_PRINCIPAL_UNKNOWN,
                    string.Empty,
                    tgsReq.Body.Realm,
                    tgsReq.Body.SName.FullyQualifiedName
                );
            }

            // renewal is an odd case here because the SName will be krbtgt
            // does this need to be validated more than the Decrypt call?

            this.EvaluateSecurityPolicy(context.Principal, context.ServicePrincipal);

            KerberosKey serviceKey;

            if (tgsReq.Body.KdcOptions.HasFlag(KdcOptions.EncTktInSkey))
            {
                serviceKey = GetUserToUserTicketKey(tgsReq.Body.AdditionalTickets, context);
            }
            else
            {
                serviceKey = context.ServicePrincipal.RetrieveLongTermCredential();
            }

            var now = this.RealmService.Now();

            TicketFlags flags = 0;

            if (tgsReq.Body.KdcOptions.HasFlag(KdcOptions.Forwardable))
            {
                flags |= TicketFlags.Forwardable;
            }

            if (context.Ticket.Flags.HasFlag(TicketFlags.PreAuthenticated))
            {
                flags |= TicketFlags.PreAuthenticated;
            }

            if (context.IncludePac == null)
            {
                context.IncludePac = DetectPacRequirement(tgsReq);

                if (context.IncludePac == null)
                {
                    context.IncludePac = context.Ticket?.AuthorizationData?.Any(a => a.Type == AuthorizationDataType.AdIfRelevant) ?? false;
                }
            }

            var rst = new ServiceTicketRequest
            {
                KdcAuthorizationKey = context.EvidenceTicketKey,
                Principal = context.Principal,
                EncryptedPartKey = context.EncryptedPartKey,
                EncryptedPartEType = context.EncryptedPartEType,
                ServicePrincipal = context.ServicePrincipal,
                ServicePrincipalKey = serviceKey,
                RealmName = tgsReq.Body.Realm,
                Addresses = tgsReq.Body.Addresses,
                RenewTill = context.Ticket.RenewTill,
                StartTime = tgsReq.Body.From ?? DateTimeOffset.MinValue,
                EndTime = tgsReq.Body.Till,
                MaximumTicketLifetime = this.RealmService.Settings.SessionLifetime,
                Flags = flags,
                Now = now,
                Nonce = tgsReq.Body.Nonce,
                IncludePac = context.IncludePac ?? false,
                PreferredClientEType = GetPreferredEType(
                    tgsReq.Body.EType,
                    this.RealmService.Configuration.Defaults.PermittedEncryptionTypes,
                    this.RealmService.Configuration.Defaults.AllowWeakCrypto
                ),
                Compatibility = this.RealmService.Settings.Compatibility,
            };

            if (tgsReq.Body.KdcOptions.HasFlag(KdcOptions.Canonicalize))
            {
                rst.SamAccountName = context.GetState<TgsState>(PaDataType.PA_TGS_REQ).DecryptedApReq.Ticket.CName.FullyQualifiedName;
            }

            // this is set here instead of in GenerateServiceTicket because GST is used by unit tests to
            // generate tickets with weird lifetimes for scenario testing and we don't want to break that

            rst.ClampLifetime();

            var tgsRep = KrbKdcRep.GenerateServiceTicket<KrbTgsRep>(rst);

            return tgsRep.EncodeApplication();
        }

        private IKerberosPrincipal ProposeTransitedRealm(KrbTgsReq tgsReq, PreAuthenticationContext context)
        {
            if (this.RealmService.TrustedRealms == null)
            {
                return null;
            }

            // the requested sname is not in our realm so we need to find a realm we think can issue a ticket for them
            // we also can't really determine if that realm can fulfill the request through any fixed logic so we'll
            // defer to the realm service and they can provide their own logic

            var realm = this.RealmService.TrustedRealms.ProposeTransit(tgsReq, context);

            if (realm != null)
            {
                return realm.Refer();
            }

            return null;
        }

        private static KerberosKey GetUserToUserTicketKey(KrbTicket[] tickets, PreAuthenticationContext context)
        {
            if (tickets == null || tickets.Length <= 0)
            {
                throw new InvalidOperationException("User to User authentication was requested but a ticket wasn't provided");
            }

            var ticket = tickets[0];

            var decryptedTicket = ticket.EncryptedPart.Decrypt(
                context.EvidenceTicketKey,
                KeyUsage.Ticket,
                b => KrbEncTicketPart.DecodeApplication(b)
            );

            return decryptedTicket.Key.AsKey();
        }

        protected virtual void EvaluateSecurityPolicy(
            IKerberosPrincipal principal,
            IKerberosPrincipal servicePrincipal
        )
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            if (servicePrincipal == null)
            {
                throw new ArgumentNullException(nameof(servicePrincipal));
            }

            this.logger.LogDebug("Default policy evaluated for {User} to {Service}", principal.PrincipalName, servicePrincipal.PrincipalName);

            // good place to check whether the incoming principal is allowed to access the service principal
        }
    }
}
