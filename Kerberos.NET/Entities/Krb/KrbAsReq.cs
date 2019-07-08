using Kerberos.NET.Asn1;
using Kerberos.NET.Client;
using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.Asn1;
using System.Text;

namespace Kerberos.NET.Entities
{
    public partial class KrbAsReq
    {
        private static readonly Asn1Tag ApplicationTag = new Asn1Tag(TagClass.Application, 10);

        public ReadOnlyMemory<byte> EncodeAsApplication()
        {
            using (var writer = new AsnWriter(AsnEncodingRules.DER))
            {
                writer.PushSequence(ApplicationTag);

                if (this.AsReq != null)
                {
                    this.AsReq?.Encode(writer);
                }

                writer.PopSequence(ApplicationTag);

                var span = writer.EncodeAsSpan();

                return span.AsMemory();
            }
        }

        public DateTimeOffset DecryptTimestamp(KerberosKey key)
        {
            var timestampPaData = AsReq?.PaData.FirstOrDefault(p => p.Type == PaDataType.PA_ENC_TIMESTAMP);

            if (timestampPaData == null)
            {
                return DateTimeOffset.MinValue;
            }

            var encryptedTimestamp = KrbEncryptedData.Decode(timestampPaData.Value);

            var tsEnc = encryptedTimestamp.Decrypt(key, KeyUsage.PaEncTs, d => KrbPaEncTsEnc.Decode(d));

            var timestamp = tsEnc.PaTimestamp;

            if (tsEnc.PaUSec > 0)
            {
                timestamp = timestamp.AddTicks(tsEnc.PaUSec.Value / 10);
            }

            return timestamp;
        }

        public static KrbAsReq CreateAsReq(KerberosCredential credential, AuthenticationOptions options)
        {
            var kdcOptions = (KdcOptions)(options & ~AuthenticationOptions.AllAuthentication);

            var hostAddress = Environment.MachineName;

            var padata = new List<KrbPaData>() {
                new KrbPaData
                {
                    Type = PaDataType.PA_PAC_REQUEST,
                    Value = new ReadOnlyMemory<byte>(new KrbPaPacRequest
                    {
                        IncludePac = options.HasFlag(AuthenticationOptions.IncludePacRequest)
                    }.Encode().ToArray())
                }
            };

            if (options.HasFlag(AuthenticationOptions.PreAuthenticate))
            {
                KerberosConstants.Now(out DateTimeOffset timestamp, out int usec);

                var ts = new KrbPaEncTsEnc
                {
                    PaTimestamp = timestamp,
                    PaUSec = usec
                };

                var tsEncoded = ts.Encode().AsMemory();

                KrbEncryptedData encData = KrbEncryptedData.Encrypt(
                    tsEncoded,
                    credential.CreateKey(),
                    KeyUsage.PaEncTs
                );

                padata.Add(new KrbPaData
                {
                    Type = PaDataType.PA_ENC_TIMESTAMP,
                    Value = encData.Encode().AsMemory()
                });
            }

            var asreq = new KrbAsReq()
            {
                AsReq = new KrbKdcReq()
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
                }
            };

            return asreq;
        }
    }
}
