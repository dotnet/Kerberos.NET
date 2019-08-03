using Kerberos.NET.Asn1;
using Kerberos.NET.Crypto;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Kerberos.NET.Entities
{
    public partial class KrbTgsReq : IAsn1ApplicationEncoder<KrbTgsReq>, IKerberosMessage
    {
        public KrbTgsReq()
        {
            MessageType = MessageType.KRB_TGS_REQ;
        }

        public MessageType KerberosMessageType => MessageType;

        public string Realm => Body.Realm;

        public int KerberosProtocolVersionNumber => ProtocolVersionNumber;

        public KrbTgsReq DecodeAsApplication(ReadOnlyMemory<byte> encoded)
        {
            return DecodeApplication(encoded);
        }

        public static KrbTgsReq CreateTgsReq(
            string spn,
            KrbEncryptionKey tgtSessionKey,
            KrbKdcRep kdcRep,
            KdcOptions options,
            KrbTicket user2UserTicket = null
        )
        {
            var tgtApReq = CreateApReq(kdcRep, tgtSessionKey);

            var pacOptions = new KrbPaPacOptions
            {
                Flags = PacOptions.ResourceBasedConstrainedDelegation | PacOptions.Claims | PacOptions.BranchAware
            }.Encode();

            var paData = new List<KrbPaData>() {
                new KrbPaData {
                    Type = PaDataType.PA_TGS_REQ,
                    Value = tgtApReq.EncodeApplication()
                },
                new KrbPaData {
                    Type = PaDataType.PA_PAC_OPTIONS,
                    Value = pacOptions.AsMemory()
                }
            };

            var tgt = kdcRep.Ticket;

            var sname = spn.Split('/', '@');

            var tgs = new KrbTgsReq
            {
                PaData = paData.ToArray(),
                Body = new KrbKdcReqBody
                {
                    EType = KerberosConstants.ETypes.ToArray(),
                    KdcOptions = options,
                    Nonce = KerberosConstants.GetNonce(),
                    Realm = tgt.Realm,
                    SName = new KrbPrincipalName()
                    {
                        Type = PrincipalNameType.NT_SRV_HST,
                        Name = sname
                    },
                    Till = KerberosConstants.EndOfTime
                },
            };

            if (options.HasFlag(KdcOptions.EncTktInSkey) && user2UserTicket != null)
            {
                tgs.Body.AdditionalTickets = new[] {
                    user2UserTicket
                };
            }

            return tgs;
        }

        private static KrbApReq CreateApReq(KrbKdcRep kdcRep, KrbEncryptionKey tgtSessionKey)
        {
            var tgt = kdcRep.Ticket;

            KerberosConstants.Now(out DateTimeOffset time, out int usec);

            var authenticator = new KrbAuthenticator
            {
                CName = kdcRep.CName,
                CTime = time,
                Cusec = usec,
                Realm = tgt.Realm,
                SequenceNumber = KerberosConstants.GetNonce(),
                Subkey = tgtSessionKey,
                AuthenticatorVersionNumber = 5
            };

            var encryptedAuthenticator = KrbEncryptedData.Encrypt(
                authenticator.EncodeApplication(),
                tgtSessionKey.AsKey(),
                KeyUsage.PaTgsReqAuthenticator
            );

            var apReq = new KrbApReq
            {
                Ticket = tgt,
                Authenticator = encryptedAuthenticator
            };

            return apReq;
        }
    }
}
