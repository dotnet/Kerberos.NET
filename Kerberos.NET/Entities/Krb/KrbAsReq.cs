using Kerberos.NET.Client;
using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Kerberos.NET.Entities
{
    public partial class KrbAsReq : IKerberosMessage
    {
        public KrbAsReq()
        {
            MessageType = MessageType.KRB_AS_REQ;
        }

        public MessageType KerberosMessageType => MessageType;

        public string Realm => Body.Realm;

        public int KerberosProtocolVersionNumber => ProtocolVersionNumber;

        public static KrbAsReq CreateAsReq(KerberosCredential credential, AuthenticationOptions options)
        {
            var kdcOptions = (KdcOptions)(options & ~AuthenticationOptions.AllAuthentication);

            var hostAddress = Environment.MachineName;

            var pacRequest = new KrbPaPacRequest
            {
                IncludePac = options.HasFlag(AuthenticationOptions.IncludePacRequest)
            };

            var padata = new List<KrbPaData>()
            {
                new KrbPaData
                {
                    Type = PaDataType.PA_PAC_REQUEST,
                    Value = pacRequest.Encode()
                }
            };

            if (options.HasFlag(AuthenticationOptions.PreAuthenticate))
            {
                var ts = KrbPaEncTsEnc.Now();

                var tsEncoded = ts.Encode();

                KrbEncryptedData encData = KrbEncryptedData.Encrypt(
                    tsEncoded,
                    credential.CreateKey(),
                    KeyUsage.PaEncTs
                );

                padata.Add(new KrbPaData
                {
                    Type = PaDataType.PA_ENC_TIMESTAMP,
                    Value = encData.Encode()
                });
            }

            var asreq = new KrbAsReq()
            {
                MessageType = MessageType.KRB_AS_REQ,
                Body = new KrbKdcReqBody
                {
                    Addresses = new[] {
                            new KrbHostAddress {
                                AddressType = AddressType.NetBios,
                                Address = Encoding.ASCII.GetBytes(hostAddress.PadRight(16, ' '))
                            }
                        },
                    CName = new KrbPrincipalName
                    {
                        Name = new[] { $"{credential.UserName}@{credential.Domain}" },
                        Type = PrincipalNameType.NT_ENTERPRISE
                    },
                    EType = KerberosConstants.ETypes.ToArray(),
                    KdcOptions = kdcOptions,
                    Nonce = KerberosConstants.GetNonce(),
                    RTime = KerberosConstants.EndOfTime,
                    Realm = credential.Domain,
                    SName = new KrbPrincipalName
                    {
                        Type = PrincipalNameType.NT_SRV_INST,
                        Name = new[] { "krbtgt", credential.Domain }
                    },
                    Till = KerberosConstants.EndOfTime
                },
                PaData = padata.ToArray()
            };

            return asreq;
        }
    }
}
