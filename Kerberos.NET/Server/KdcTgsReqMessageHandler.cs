using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Microsoft.Extensions.Logging;

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
        //

        private static readonly IEnumerable<PaDataType> ExpectedPreAuthTypes = new[] { PaDataType.PA_TGS_REQ };

        private readonly ILogger<KdcTgsReqMessageHandler> logger;

        public KdcTgsReqMessageHandler(ReadOnlyMemory<byte> message, ListenerOptions options)
            : base(message, options)
        {
            logger = options.Log.CreateLoggerSafe<KdcTgsReqMessageHandler>();

            PreAuthHandlers[PaDataType.PA_TGS_REQ] = service => new PaDataTgsTicketHandler(service);
        }

        protected override IKerberosMessage DecodeMessageCore(ReadOnlyMemory<byte> message)
        {
            var tgsReq = KrbTgsReq.DecodeApplication(message);

            SetRealmContext(tgsReq.Realm);

            return tgsReq;
        }

        protected override MessageType MessageType => MessageType.KRB_TGS_REQ;

        protected override IEnumerable<PaDataType> GetOrderedPreAuth(PreAuthenticationContext preauth) => ExpectedPreAuthTypes;

        public override void QueryPreValidate(PreAuthenticationContext context)
        {
            if (context.EvidenceTicketIdentity != null)
            {
                return;
            }

            var apReq = PaDataTgsTicketHandler.ExtractApReq(context);

            context.EvidenceTicketIdentity = RealmService.Principals.Find(apReq.Ticket.SName);
        }

        public override async Task QueryPreValidateAsync(PreAuthenticationContext context)
        {
            if (context.EvidenceTicketIdentity != null)
            {
                return;
            }

            var apReq = PaDataTgsTicketHandler.ExtractApReq(context);

            context.EvidenceTicketIdentity = await RealmService.Principals.FindAsync(apReq.Ticket.SName);
        }

        public override void ValidateTicketRequest(PreAuthenticationContext context)
        {
            ProcessPreAuth(context);

            if (!context.PreAuthenticationSatisfied)
            {
                throw new KerberosProtocolException(KerberosErrorCode.KDC_ERR_PADATA_TYPE_NOSUPP);
            }

            var state = context.GetState<TgsState>(PaDataType.PA_TGS_REQ);

            if (state.DecryptedApReq == null)
            {
                throw new KerberosProtocolException(KerberosErrorCode.KDC_ERR_BADOPTION);
            }

            // now that we have the identity from the ticket we duplicate all its interesting bits
            // to include in the requested service ticket but excluding any potentially dangerous
            // authz values if it's from a referred realm

            // NOTE: Transform should never be async. 
            // It should eventually be a fast transform once the todo is resolved

            var principal = TransformClientIdentity(state.DecryptedApReq, context.EvidenceTicketIdentity);

            // this should never hit since we just copy the principal information from the krbtgt
            // but callers can override TransformClientIdentity so lets fail quickly to be safe

            context.Principal = principal ?? throw new KerberosProtocolException(KerberosErrorCode.KDC_ERR_C_PRINCIPAL_UNKNOWN);
        }

        protected virtual IKerberosPrincipal TransformClientIdentity(
            DecryptedKrbApReq clientTicket,
            IKerberosPrincipal ticketIssuerIdentity
        )
        {
            if (ticketIssuerIdentity.Type == PrincipalType.TrustedDomain)
            {
                // it's a referral from another realm so all the copy and filter
                // goop is in TransitedKerberosPrincipal.GeneratePac()

                return new TransitedKerberosPrincipal(clientTicket);
            }

            // TODO: shouldn't be calling Find(), but instead copying the existing PAC
            // This won't need an async call because it'll eventually go away

            return RealmService.Principals.Find(clientTicket.Ticket.CName);
        }

        public override void QueryPreExecute(PreAuthenticationContext context)
        {
            var tgsReq = (KrbTgsReq)context.Message;

            logger.LogInformation("TGS-REQ incoming. SPN = {SPN}", tgsReq.Body.SName.FullyQualifiedName);

            context.ServicePrincipal = RealmService.Principals.Find(tgsReq.Body.SName);
        }

        public override async Task QueryPreExecuteAsync(PreAuthenticationContext context)
        {
            var tgsReq = (KrbTgsReq)context.Message;

            logger.LogInformation("TGS-REQ incoming. SPN = {SPN}", tgsReq.Body.SName.FullyQualifiedName);

            context.ServicePrincipal = await RealmService.Principals.FindAsync(tgsReq.Body.SName);
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

            var tgsReq = (KrbTgsReq)context.Message;

            if (context.ServicePrincipal == null)
            {
                // we can't find what they're asking for, but maybe it's in a realm we can transit?

                context.ServicePrincipal = ProposeTransitedRealm(tgsReq, context);
            }

            if (context.ServicePrincipal == null)
            {
                // we have no idea what service they're asking for and
                // there isn't a realm we can refer them to that can issue a ticket

                return GenerateError(
                    KerberosErrorCode.KDC_ERR_S_PRINCIPAL_UNKNOWN,
                    "",
                    RealmService.Name,
                    tgsReq.Body.SName.FullyQualifiedName
                );
            }

            // renewal is an odd case here because the SName will be krbtgt
            // does this need to be validated more than the Decrypt call?

            EvaluateSecurityPolicy(context.Principal, context.ServicePrincipal);

            KerberosKey serviceKey;

            if (tgsReq.Body.KdcOptions.HasFlag(KdcOptions.EncTktInSkey))
            {
                serviceKey = GetUserToUserTicketKey(tgsReq.Body.AdditionalTickets, context);
            }
            else
            {
                serviceKey = context.ServicePrincipal.RetrieveLongTermCredential();
            }

            var now = RealmService.Now();

            TicketFlags flags = 0;

            if (tgsReq.Body.KdcOptions.HasFlag(KdcOptions.Forwardable))
            {
                flags |= TicketFlags.Forwardable;
            }

            if (context.Ticket.Flags.HasFlag(TicketFlags.PreAuthenticated))
            {
                flags |= TicketFlags.PreAuthenticated;
            }

            var includePac = DetectPacRequirement(tgsReq);

            if (includePac == null)
            {
                includePac = context.Ticket?.AuthorizationData?.Any(a => a.Type == AuthorizationDataType.AdIfRelevant) ?? false;
            }

            var tgsRep = KrbKdcRep.GenerateServiceTicket<KrbTgsRep>(
                new ServiceTicketRequest
                {
                    KdcAuthorizationKey = context.EvidenceTicketKey,
                    Principal = context.Principal,
                    EncryptedPartKey = context.EncryptedPartKey,
                    ServicePrincipal = context.ServicePrincipal,
                    ServicePrincipalKey = serviceKey,
                    RealmName = RealmService.Name,
                    Addresses = tgsReq.Body.Addresses,
                    RenewTill = context.Ticket.RenewTill,
                    StartTime = now - RealmService.Settings.MaximumSkew,
                    EndTime = now + RealmService.Settings.SessionLifetime,
                    Flags = flags,
                    Now = now,
                    Nonce = tgsReq.Body.Nonce,
                    IncludePac = includePac ?? false
                }
            );

            return tgsRep.EncodeApplication();
        }

        private IKerberosPrincipal ProposeTransitedRealm(KrbTgsReq tgsReq, PreAuthenticationContext context)
        {
            if (RealmService.TrustedRealms == null)
            {
                return null;
            }

            // the requested sname is not in our realm so we need to find a realm we think can issue a ticket for them
            // we also can't really determine if that realm can fulfill the request through any fixed logic so we'll
            // defer to the realm service and they can provide their own logic

            var realm = RealmService.TrustedRealms.ProposeTransit(tgsReq, context);

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
            logger.LogDebug("Default policy evaluated for {User} to {Service}", principal.PrincipalName, servicePrincipal.PrincipalName);

            // good place to check whether the incoming principal is allowed to access the service principal
        }
    }
}
