using Kerberos.NET.Asn1;
using Kerberos.NET.Crypto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.Asn1;

namespace Kerberos.NET.Entities
{
    public partial class KrbTgsReq : IAsn1ApplicationEncoder<KrbTgsReq>
    {
        internal const int ApplicationTagValue = 12;

        private static readonly Asn1Tag ApplicationTag = new Asn1Tag(TagClass.Application, ApplicationTagValue);

        public KrbTgsReq()
        {
        }

        public static KrbTgsReq DecodeMessageAsApplication(ReadOnlyMemory<byte> message)
        {
            return Decode(ApplicationTag, message);
        }

        public KrbTgsReq DecodeAsApplication(ReadOnlyMemory<byte> message)
        {
            return Decode(ApplicationTag, message);
        }

        public ReadOnlyMemory<byte> EncodeAsApplication()
        {
            using (var writer = new AsnWriter(AsnEncodingRules.DER))
            {
                writer.PushSequence(ApplicationTag);

                if (TgsReq != null)
                {
                    TgsReq.Encode(writer);
                }

                writer.PopSequence(ApplicationTag);

                var span = writer.EncodeAsSpan();

                return span.AsMemory();
            }
        }

        public static KrbTgsReq CreateTgsReq(string spn, KrbEncryptionKey tgtSessionKey, KrbKdcRep kdcRep, KdcOptions options)
        {
            var tgtApReq = CreateApReq(kdcRep, tgtSessionKey);

            var pacOptions = new KrbPaPacOptions
            {
                Flags = PacOptions.ResourceBasedConstrainedDelegation | PacOptions.Claims | PacOptions.BranchAware
            }.Encode();

            var paData = new List<KrbPaData>() {
                new KrbPaData {
                    Type = PaDataType.PA_TGS_REQ,
                    Value = tgtApReq.EncodeAsApplication()
                },
                new KrbPaData {
                    Type = PaDataType.PA_PAC_OPTIONS,
                    Value = pacOptions.AsMemory()
                }
            };

            var tgt = kdcRep.Ticket.Application;

            var sname = spn.Split('/', '@');

            var tgs = new KrbTgsReq
            {
                TgsReq = new KrbKdcReq
                {
                    MessageType = MessageType.KRB_TGS_REQ,
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
                    }
                },
            };

            return tgs;
        }

        private static KrbApReq CreateApReq(KrbKdcRep kdcRep, KrbEncryptionKey tgtSessionKey)
        {
            var tgt = kdcRep.Ticket.Application;

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
                authenticator.EncodeAsApplication(),
                tgtSessionKey.AsKey(),
                KeyUsage.PaTgsReqAuthenticator
            );

            var apReq = new KrbApReq
            {
                Ticket = new KrbTicketApplication { Application = tgt },
                Authenticator = encryptedAuthenticator
            };

            return apReq;
        }
    }
}
