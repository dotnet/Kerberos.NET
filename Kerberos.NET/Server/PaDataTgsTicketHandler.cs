using System.Linq;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;

namespace Kerberos.NET.Server
{
    public class PaDataTgsTicketHandler : KdcPreAuthenticationHandlerBase
    {
        public PaDataTgsTicketHandler(IRealmService service)
            : base(service)
        {

        }

        public ValidationActions Validation { get; set; } = ValidationActions.All & ~ValidationActions.Replay;

        /// <summary>
        /// Executes before the validation stage and can be used for initial decoding of the message.
        /// </summary>
        /// <param name="preauth"></param>
        public override void PreValidate(PreAuthenticationContext preauth)
        {
            ExtractApReq(preauth);

            if (preauth.EvidenceTicketKey == null)
            {
                return;
            }

            var state = preauth.GetState<TgsState>(PaDataType.PA_TGS_REQ);

            state.DecryptedApReq = DecryptApReq(state.ApReq, preauth.EvidenceTicketKey);
        }

        /// <summary>
        /// Executes the primary validation process for the pre-auth data.
        /// </summary>
        /// <param name="asReq">The message to validate</param>
        /// <param name="context">The current context of the request</param>
        /// <returns>Optionally returns PA-Data that needs to be sent to the client otherwise returns null.</returns>
        public override KrbPaData Validate(KrbKdcReq asReq, PreAuthenticationContext context)
        {
            // First we authenticate the incoming request
            //
            // 1. Get the ApReq (TGT) from the PA-Data of the request
            // 2. Decrypt the TGT and extract the client calling identity

            if (context.EvidenceTicketIdentity == null)
            {
                // we wouldn't ever hit this in the normal case, but we could hit it
                // if a referral came in from a realm we don't recognize or don't trust

                throw new KerberosProtocolException(KerberosErrorCode.KDC_ERR_S_PRINCIPAL_UNKNOWN);
            }

            var evidenceSName = KrbPrincipalName.FromPrincipal(context.EvidenceTicketIdentity, PrincipalNameType.NT_SRV_INST);

            if (!evidenceSName.IsKrbtgt())
            {
                // spec-wise this isn't exactly correct as the authz ticket might be for renewal
                // we will deviate from the spec because that's how other KDCs operate today
                // KDC_ERR_PADATA_TYPE_NOSUPP is the closest error to indicate the way you
                // authenticated the request is not something we're willing to accept

                throw new KerberosProtocolException(KerberosErrorCode.KDC_ERR_PADATA_TYPE_NOSUPP);
            }

            // we need to validate that the evidence ticket is the KDC service (krbtgt)
            // it might either be our KDC that issued it, or a KDC from another realm (referral)
            // if it's ours it'll match our service name (krbtgt), and it'll decrypt with our key
            // if it's a referral it'll match a trusted realm's name and decrypt with their key
            // if it's a referral then the incoming identity will also need to be transposed

            // no matter what we only ever want the TGS service ticket
            // it might belong to another realm, but that's ok because it could be a referral

            // it is a krbtgt service identity we recognize
            // it could be ours, or a referral from a trusted realm
            // in either case we can and will validate the ticket and
            // extract the user principal from within the krbtgt ticket

            var krbtgtKey = context.EvidenceTicketIdentity.RetrieveLongTermCredential();

            if (krbtgtKey == null)
            {
                // since the key comes from caller-implemented code we
                // should check to make sure they gave us a usable key

                throw new KerberosProtocolException(KerberosErrorCode.KDC_ERR_ETYPE_NOSUPP);
            }

            if (context.EvidenceTicketKey == null)
            {
                context.EvidenceTicketKey = krbtgtKey;
            }

            var state = context.GetState<TgsState>(PaDataType.PA_TGS_REQ);

            if (state.DecryptedApReq == null)
            {
                state.DecryptedApReq = DecryptApReq(state.ApReq, context.EvidenceTicketKey);
            }

            context.EncryptedPartKey = state.DecryptedApReq.SessionKey;
            context.Ticket = state.DecryptedApReq.Ticket;

            return null;
        }

        /// <summary>
        /// Locate the AP-REQ in the PA-Data of a TGS-REQ.
        /// </summary>
        /// <param name="context">The current contex of the request.</param>
        /// <returns>Returns the AP-REQ message within the TGS-REQ PA-Data.</returns>
        public static KrbApReq ExtractApReq(PreAuthenticationContext context)
        {
            var state = context.GetState<TgsState>(PaDataType.PA_TGS_REQ);

            if (state.ApReq == null)
            {
                var tgsReq = (KrbTgsReq)context.Message;

                var paData = tgsReq.PaData.First(p => p.Type == PaDataType.PA_TGS_REQ);

                state.ApReq = paData.DecodeApReq();
            }

            return state.ApReq;
        }

        private DecryptedKrbApReq DecryptApReq(KrbApReq apReq, KerberosKey krbtgtKey)
        {
            var apReqDecrypted = new DecryptedKrbApReq(apReq, MessageType.KRB_TGS_REQ);

            apReqDecrypted.Decrypt(krbtgtKey);

            apReqDecrypted.Validate(Validation);

            return apReqDecrypted;
        }
    }
}
