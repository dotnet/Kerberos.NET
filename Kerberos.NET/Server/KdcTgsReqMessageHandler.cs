using Kerberos.NET.Asn1;
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

        public ValidationActions Validation { get; set; } = ValidationActions.All & ~ValidationActions.Replay;

        protected override async Task<ReadOnlyMemory<byte>> ExecuteCore(ReadOnlyMemory<byte> message)
        {
            var tgsReqMessage = KrbTgsReq.DecodeMessageAsApplication(message);

            var tgsReq = tgsReqMessage.TgsReq;

            await SetRealmContext(tgsReq.Body.Realm);
            
            var paData = tgsReq.PaData.First(p => p.Type == PaDataType.PA_TGS_REQ);

            var apReq = paData.DecodeApReq();

            var krbtgtIdentity = await RealmService.Principals.RetrieveKrbtgt();
            var krbtgtKey = await krbtgtIdentity.RetrieveLongTermCredential();

            var apReqDecrypted = new DecryptedKrbApReq(apReq, MessageType.KRB_TGS_REQ);

            apReqDecrypted.Decrypt(krbtgtKey);

            apReqDecrypted.Validate(Validation);

            var principal = await RealmService.Principals.Find(apReqDecrypted.Ticket.CName.FullyQualifiedName);

            var servicePrincipal = await RealmService.Principals.Find(tgsReq.Body.SName.FullyQualifiedName);

            // TODO: move GenerateServiceTicket to KrbKdcRep because it's all the same message

            //var serviceTicket = await KrbAsRep.GenerateServiceTicket(principal, servicePrincipal, RealmService, MessageType.KRB_TGS_REP);

            //var tgsRep = new KrbTgsRep {
            //    Response = new KrbKdcRep {
            //        CName = KrbPrincipalName.FromPrincipal(principal, realm: RealmService.Name),
            //        CRealm = RealmService.Name,
            //        MessageType = MessageType.KRB_TGS_REP,
            //        Ticket = serviceTicket.Response.Ticket,
            //        EncPart = KrbEncryptedData.Encrypt(
            //            tgsRepPart.Encode().AsMemory(), 
            //            apReqDecrypted.SessionKey, 
            //            KeyUsage.EncTgsRepPartSubSessionKey
            //        )
            //    }
            //};

            throw new NotImplementedException("TGS-REQ is not implemented yet");
        }
    }
}