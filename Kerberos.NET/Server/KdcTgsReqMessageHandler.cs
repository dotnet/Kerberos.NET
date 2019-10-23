using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Microsoft.Extensions.Logging;
using System;
using System.Buffers;
using System.Linq;
using System.Threading.Tasks;

namespace Kerberos.NET.Server
{
    internal class KdcTgsReqMessageHandler : KdcMessageHandlerBase
    {
        private readonly ILogger<KdcTgsReqMessageHandler> logger;

        public KdcTgsReqMessageHandler(ReadOnlySequence<byte> message, ListenerOptions options)
            : base(message, options)
        {
            logger = options.Log.CreateLoggerSafe<KdcTgsReqMessageHandler>();
        }

        // a krbtgt ticket will be replayed repeatedly, so maybe lets not fail validation on that
        // unless a higher power indicates we should

        public ValidationActions Validation { get; set; } = ValidationActions.All & ~ValidationActions.Replay;

        protected override IKerberosMessage DecodeMessageCore(ReadOnlyMemory<byte> message)
        {
            return KrbTgsReq.DecodeApplication(message);
        }

        protected override MessageType MessageType => MessageType.KRB_TGS_REQ;

        protected override async Task<ReadOnlyMemory<byte>> ExecuteCore(IKerberosMessage message)
        {
            // the logic for a TGS-REQ is relatively simple in the primary case where you have a TGT and want
            // to get a ticket to another service. It gets a bit more complicated when you need to do something
            // like a U2U exchange, renew, or get a referral to another realm. Realm referral isn't supported yet.

            // 1. Get the ApReq (TGT) from the PA-Data of the request
            // 2. Decrypt the TGT and extract the client calling identity
            // 3. Find the requested service principal
            // 4. Evaluate whether the client identity should get a ticket to the service
            // 5. Evaluate whether it should do U2U and if so extract that key instead
            // 6. Generate a service ticket for the calling client to the service
            // 7. return to client

            var tgsReq = (KrbTgsReq)message;

            var apReq = ExtractApReq(tgsReq);

            logger.LogInformation("TGS-REQ incoming. SPN = {SPN}", tgsReq.Body.SName.FullyQualifiedName);

            var krbtgtIdentity = await RealmService.Principals.RetrieveKrbtgt();
            var krbtgtKey = await krbtgtIdentity.RetrieveLongTermCredential();

            var krbtgtApReqDecrypted = DecryptApReq(apReq, krbtgtKey);

            var principal = await RealmService.Principals.Find(krbtgtApReqDecrypted.Ticket.CName.FullyQualifiedName);

            var servicePrincipal = await RealmService.Principals.Find(tgsReq.Body.SName.FullyQualifiedName);

            // renewal is an odd case here because the SName will be krbtgt
            // does this need to be validated more than the Decrypt call?

            await EvaluateSecurityPolicy(principal, servicePrincipal, krbtgtApReqDecrypted);

            KerberosKey serviceKey;

            if (tgsReq.Body.KdcOptions.HasFlag(KdcOptions.EncTktInSkey))
            {
                serviceKey = GetUserToUserTicketKey(tgsReq.Body.AdditionalTickets, krbtgtKey);
            }
            else
            {
                serviceKey = await servicePrincipal.RetrieveLongTermCredential();
            }

            var now = RealmService.Now();

            var tgsRep = await KrbKdcRep.GenerateServiceTicket<KrbTgsRep>(
                new ServiceTicketRequest
                {
                    Principal = principal,
                    EncryptedPartKey = krbtgtApReqDecrypted.SessionKey,
                    ServicePrincipal = servicePrincipal,
                    ServicePrincipalKey = serviceKey,
                    RealmName = RealmService.Name,
                    Addresses = tgsReq.Body.Addresses,
                    RenewTill = krbtgtApReqDecrypted.Ticket.RenewTill,
                    StartTime = now - RealmService.Settings.MaximumSkew,
                    EndTime = now + RealmService.Settings.SessionLifetime,
                    Flags = KrbKdcRep.DefaultFlags,
                    Now = now,
                    IncludePac = krbtgtApReqDecrypted.Ticket.AuthorizationData.Any(a => a.Type == AuthorizationDataType.AdIfRelevant)
                }
            );

            return tgsRep.EncodeApplication();
        }

        private static KerberosKey GetUserToUserTicketKey(KrbTicket[] tickets, KerberosKey key)
        {
            if (tickets == null || tickets.Length <= 0)
            {
                throw new InvalidOperationException("User to User authentication was requested but a ticket wasn't provided");
            }

            var ticket = tickets[0];

            var decryptedTicket = ticket.EncryptedPart.Decrypt(
                key,
                KeyUsage.Ticket,
                b => KrbEncTicketPart.DecodeApplication(b)
            );

            return decryptedTicket.Key.AsKey();
        }

        protected virtual Task EvaluateSecurityPolicy(
            IKerberosPrincipal principal,
            IKerberosPrincipal servicePrincipal,
            DecryptedKrbApReq apReqDecrypted
        )
        {
            logger.LogDebug("Evaluating policy for {User} to {Service}", principal.PrincipalName, servicePrincipal.PrincipalName);

            // good place to check whether the incoming principal is allowed to access the service principal
            // TODO: also maybe a good place to evaluate cross-realm requirements?

            return Task.CompletedTask;
        }

        private DecryptedKrbApReq DecryptApReq(KrbApReq apReq, KerberosKey krbtgtKey)
        {
            var apReqDecrypted = new DecryptedKrbApReq(apReq, MessageType.KRB_TGS_REQ);

            apReqDecrypted.Decrypt(krbtgtKey);

            apReqDecrypted.Validate(Validation);

            return apReqDecrypted;
        }

        private static KrbApReq ExtractApReq(KrbTgsReq tgsReq)
        {
            var paData = tgsReq.PaData.First(p => p.Type == PaDataType.PA_TGS_REQ);

            return paData.DecodeApReq();
        }
    }
}
