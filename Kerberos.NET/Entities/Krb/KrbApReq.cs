using Kerberos.NET.Asn1;
using Kerberos.NET.Crypto;
using System;
using System.Security.Cryptography.Asn1;

namespace Kerberos.NET.Entities
{
    public partial class KrbApReq
    {
        public KrbApReq()
        {
            ProtocolVersionNumber = 5;
            MessageType = MessageType.KRB_AP_REQ;
        }

        private static readonly Asn1Tag ApplicationTag = new Asn1Tag(TagClass.Application, 14);

        public ReadOnlyMemory<byte> EncodeAsApplication()
        {
            using (var writer = new AsnWriter(AsnEncodingRules.DER))
            {
                writer.PushSequence(ApplicationTag);

                this.Encode(writer);

                writer.PopSequence(ApplicationTag);

                var span = writer.EncodeAsSpan();

                return span.AsMemory();
            }
        }

        public static KrbApReq CreateAsReq(KrbKdcRep tgsRep, KerberosKey authenticatorKey)
        {
            var ticket = tgsRep.Ticket;

            var authenticator = new KrbAuthenticator
            {
                CName = tgsRep.CName,
                CTime = DateTimeOffset.UtcNow,
                Cusec = 0,
                Realm = ticket.Application.Realm,
                SequenceNumber = KerberosConstants.GetNonce(),
                Subkey = null,
                AuthenticatorVersionNumber = 5
            };

            var apReq = new KrbApReq
            {
                Ticket = ticket,
                Authenticator = KrbEncryptedData.Encrypt(
                    authenticator.EncodeAsApplication(),
                    authenticatorKey,
                    KeyUsage.ApReqAuthenticator
                )
            };

            return apReq;
        }
    }
}
