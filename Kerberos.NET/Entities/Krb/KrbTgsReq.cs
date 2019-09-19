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
            KrbTicket user2UserTicket = null,
            string s4u = null
        )
        {
            var sname = spn.Split('/', '@');
            var tgt = kdcRep.Ticket;

            var body = new KrbKdcReqBody
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
            };

            var bodyChecksum = KrbChecksum.Create(body.Encode().AsMemory(), tgtSessionKey.AsKey(), KeyUsage.PaTgsReqChecksum);

            var tgtApReq = CreateApReq(kdcRep, tgtSessionKey, bodyChecksum);

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

            if (!string.IsNullOrWhiteSpace(s4u))
            {
                paData.Add(new KrbPaData
                {
                    Type = PaDataType.PA_FOR_USER,
                    Value = EncodeS4URequest(s4u, tgt.Realm, tgtSessionKey)
                });
            }

            var tgs = new KrbTgsReq
            {
                PaData = paData.ToArray(),
                Body = body
            };

            if (options.HasFlag(KdcOptions.EncTktInSkey) && user2UserTicket != null)
            {
                tgs.Body.AdditionalTickets = new[] {
                    user2UserTicket
                };
            }

            return tgs;
        }

        private static ReadOnlyMemory<byte> EncodeS4URequest(string s4u, string realm, KrbEncryptionKey sessionKey)
        {
            var paS4u = new KrbPaForUser
            {
                AuthPackage = "Kerberos",
                UserName = new KrbPrincipalName { Type = PrincipalNameType.NT_ENTERPRISE, Name = new[] { s4u } },
                UserRealm = realm
            };

            paS4u.GenerateChecksum(sessionKey.AsKey());

            return paS4u.Encode().AsMemory();
        }

        private static KrbApReq CreateApReq(KrbKdcRep kdcRep, KrbEncryptionKey tgtSessionKey, KrbChecksum checksum)
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
                Checksum = checksum
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
