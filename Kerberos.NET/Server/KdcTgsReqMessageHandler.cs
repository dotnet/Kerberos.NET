using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using System;
using System.Buffers;
using System.Linq;
using System.Threading.Tasks;

namespace Kerberos.NET.Server
{
    internal class KdcTgsReqMessageHandler : KdcMessageHandlerBase
    {
        public KdcTgsReqMessageHandler(ReadOnlySequence<byte> message, ListenerOptions options)
            : base(message, options)
        {
        }

        // a krbtgt ticket will be replayed repeatedly, so maybe lets not fail validation on that
        // unless a higher power indicates we should

        public ValidationActions Validation { get; set; } = ValidationActions.All & ~ValidationActions.Replay;

        protected override async Task<ReadOnlyMemory<byte>> ExecuteCore(ReadOnlyMemory<byte> message)
        {
            var tgsReq = KrbTgsReq.DecodeApplication(message);

            await SetRealmContext(tgsReq.Body.Realm);

            var apReq = ExtractApReq(tgsReq);

            var krbtgtIdentity = await RealmService.Principals.RetrieveKrbtgt();
            var krbtgtKey = await krbtgtIdentity.RetrieveLongTermCredential();

            var apReqDecrypted = DecryptApReq(apReq, krbtgtKey);

            var principal = await RealmService.Principals.Find(apReqDecrypted.Ticket.CName.FullyQualifiedName);

            var servicePrincipal = await RealmService.Principals.Find(tgsReq.Body.SName.FullyQualifiedName);

            // renewal is an odd case here because the SName will krbtgt
            // does this need to be validated more than the Decrypt call?

            await EvaluateSecurityPolicy(principal, servicePrincipal, apReqDecrypted);

            KerberosKey serviceKey;

            if (tgsReq.Body.KdcOptions.HasFlag(KdcOptions.EncTktInSkey) &&
                tgsReq.Body.AdditionalTickets != null &&
                tgsReq.Body.AdditionalTickets.Length > 0)
            {
                serviceKey = GetUserToUserTicketKey(tgsReq.Body.AdditionalTickets[0], krbtgtKey);
            }
            else
            {
                serviceKey = await servicePrincipal.RetrieveLongTermCredential();
            }

            var tgsRep = await KrbKdcRep.GenerateServiceTicket<KrbTgsRep>(
                principal,
                apReqDecrypted.SessionKey,
                servicePrincipal,
                serviceKey,
                RealmService,
                addresses: tgsReq.Body.Addresses
            );

            return tgsRep.EncodeApplication();
        }

        private static KerberosKey GetUserToUserTicketKey(KrbTicket ticket, KerberosKey key)
        {
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