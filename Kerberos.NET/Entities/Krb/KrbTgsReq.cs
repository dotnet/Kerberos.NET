using Kerberos.NET.Asn1;
using Kerberos.NET.Crypto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.Asn1;

namespace Kerberos.NET.Entities
{
    public partial class KrbTgsReq
    {
        private static readonly Asn1Tag ApplicationTag = new Asn1Tag(TagClass.Application, 12);

        public ReadOnlyMemory<byte> EncodeAsApplication()
        {
            using (var writer = new AsnWriter(AsnEncodingRules.DER))
            {
                writer.PushSequence(ApplicationTag);

                if (this.TgsReq != null)
                {
                    this.TgsReq?.Encode(writer);
                }

                writer.PopSequence(ApplicationTag);

                var span = writer.EncodeAsSpan();

                return span.AsMemory();
            }
        }

        public static KrbTgsReq CreateTgsReq(string spn, KrbEncryptionKey tgtSessionKey, KrbKdcRep kdcRep)
        {
            KrbApReq tgtApReq = CreateApReq(kdcRep, tgtSessionKey);

            var paData = new List<KrbPaData>() {
                new KrbPaData {
                    Type = PaDataType.PA_TGS_REQ,
                    Value = tgtApReq.EncodeAsApplication()
                },
                new KrbPaData {
                    Type = PaDataType.PA_PAC_OPTIONS,
                    Value = new KrbPaPacOptions {
                        Flags = KerberosFlags.Claims | KerberosFlags.BranchAware
                    }.Encode().AsMemory()
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
                        KdcOptions = KdcOptions.Canonicalize | KdcOptions.Renewable | KdcOptions.Forwardable,
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

            var authenticator = new KrbAuthenticator
            {
                CName = kdcRep.CName,
                CTime = DateTimeOffset.UtcNow,
                Cusec = 0,
                Realm = tgt.Realm,
                SequenceNumber = KerberosConstants.GetNonce(),
                Subkey = tgtSessionKey,
                AuthenticatorVersionNumber = 5
            };

            var encryptedAuthenticator = KrbEncryptedData.Encrypt(
                authenticator.EncodeAsApplication(),
                tgtSessionKey.AsKey(),
                KeyUsage.KU_PA_TGS_REQ_AUTHENTICATOR
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
