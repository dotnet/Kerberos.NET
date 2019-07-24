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

            var tgsRep = await KrbKdcRep.GenerateServiceTicket<KrbTgsRep>(
                principal,
                apReqDecrypted.SessionKey,
                servicePrincipal,
                RealmService,
                tgsReq.Body.Addresses
            );

            return tgsRep.EncodeApplication();
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