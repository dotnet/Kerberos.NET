// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.Asn1;
using System.Security.Cryptography.X509Certificates;
using Kerberos.NET.Asn1;
using Kerberos.NET.Configuration;
using Kerberos.NET.Crypto;
using static Kerberos.NET.Entities.KerberosConstants;

namespace Kerberos.NET.Entities
{
    public partial class KrbTgsReq : IAsn1ApplicationEncoder<KrbTgsReq>, IKerberosMessage
    {
        public KrbTgsReq()
        {
            this.MessageType = MessageType.KRB_TGS_REQ;
        }

        [KerberosIgnore]
        public MessageType KerberosMessageType => this.MessageType;

        [KerberosIgnore]
        public string Realm => this.Body.Realm;

        [KerberosIgnore]
        public int KerberosProtocolVersionNumber => this.ProtocolVersionNumber;

        public KrbTgsReq DecodeAsApplication(ReadOnlyMemory<byte> encoded)
        {
            return DecodeApplication(encoded);
        }

        public static KrbTgsReq CreateTgsReq(
            RequestServiceTicket rst,
            KrbEncryptionKey tgtSessionKey,
            KrbKdcRep kdcRep,
            out KrbEncryptionKey sessionKey
        )
        {
            if (kdcRep == null)
            {
                throw new ArgumentNullException(nameof(kdcRep));
            }

            if (tgtSessionKey == null)
            {
                throw new ArgumentNullException(nameof(tgtSessionKey));
            }

            if (string.IsNullOrWhiteSpace(rst.ServicePrincipalName))
            {
                throw new ArgumentNullException(nameof(rst.ServicePrincipalName));
            }

            var sname = rst.ServicePrincipalName.Split('/', '@');
            var tgt = kdcRep.Ticket;

            var additionalTickets = new List<KrbTicket>();

            if (rst.KdcOptions.HasFlag(KdcOptions.EncTktInSkey) && rst.UserToUserTicket != null)
            {
                additionalTickets.Add(rst.UserToUserTicket);
            }

            if (!string.IsNullOrWhiteSpace(rst.S4uTarget) && rst.S4uTicket != null)
            {
                throw new InvalidOperationException(SR.Resource("S4uTargetTicketBothPresent"));
            }

            if (!string.IsNullOrWhiteSpace(rst.S4uTarget))
            {
                rst.KdcOptions |= KdcOptions.Forwardable;
            }

            if (rst.S4uTicket != null)
            {
                rst.KdcOptions |= KdcOptions.ConstrainedDelegation;

                additionalTickets.Add(rst.S4uTicket);
            }

            var config = rst.Configuration ?? Krb5Config.Default();

            var body = new KrbKdcReqBody
            {
                EType = GetPreferredETypes(config.Defaults.DefaultTgsEncTypes, config.Defaults.AllowWeakCrypto).ToArray(),
                KdcOptions = rst.KdcOptions,
                Nonce = GetNonce(),
                Realm = rst.Realm,
                SName = new KrbPrincipalName()
                {
                    Type = PrincipalNameType.NT_SRV_INST,
                    Name = sname
                },
                Till = EndOfTime,
                CName = rst.CNameHint
            };

            if (additionalTickets.Count > 0)
            {
                body.AdditionalTickets = additionalTickets.ToArray();
            }

            var bodyChecksum = KrbChecksum.Create(
                body.Encode(),
                tgtSessionKey.AsKey(),
                KeyUsage.PaTgsReqChecksum
            );

            var tgtApReq = CreateApReq(kdcRep, tgtSessionKey, bodyChecksum, out sessionKey);

            var pacOptions = new KrbPaPacOptions
            {
                Flags = PacOptions.ResourceBasedConstrainedDelegation | PacOptions.Claims | PacOptions.BranchAware
            }.Encode();

            var paData = new List<KrbPaData>()
            {
                new KrbPaData
                {
                    Type = PaDataType.PA_TGS_REQ,
                    Value = tgtApReq.EncodeApplication()
                },
                new KrbPaData
                {
                    Type = PaDataType.PA_PAC_OPTIONS,
                    Value = pacOptions
                }
            };

            if (!string.IsNullOrWhiteSpace(rst.S4uTarget))
            {
                if (tgtSessionKey.EType == EncryptionType.RC4_HMAC_NT)
                {
                    paData.Add(new KrbPaData
                    {
                        Type = PaDataType.PA_FOR_USER,
                        Value = EncodeS4ULegacyRequest(rst.S4uTarget, tgt.Realm, tgtSessionKey)
                    });
                }
                else
                {
                    paData.Add(new KrbPaData
                    {
                        Type = PaDataType.PA_FOR_X509_USER,
                        Value = EncodeS4URequest(rst.S4uTarget, rst.S4uTargetCertificate, body.Nonce, tgt.Realm, sessionKey)
                    });
                }
            }

            var tgs = new KrbTgsReq
            {
                PaData = paData.ToArray(),
                Body = body
            };

            return tgs;
        }

        private static ReadOnlyMemory<byte> EncodeS4ULegacyRequest(string s4u, string realm, KrbEncryptionKey sessionKey)
        {
            var paS4u = new KrbPaForUser
            {
                AuthPackage = "Kerberos",
                UserName = new KrbPrincipalName { Type = PrincipalNameType.NT_ENTERPRISE, Name = new[] { s4u } },
                UserRealm = realm
            };

            paS4u.GenerateChecksum(sessionKey.AsKey());

            return paS4u.Encode();
        }

        private static ReadOnlyMemory<byte> EncodeS4URequest(string s4u, X509Certificate2 certificate, int nonce, string realm, KrbEncryptionKey sessionKey)
        {
            var userId = new KrbS4uUserId()
            {
                CName = new KrbPrincipalName { Type = PrincipalNameType.NT_ENTERPRISE, Name = new[] { s4u } },
                Nonce = nonce,
                Realm = realm
            };

            if (certificate != null)
            {
                userId.SubjectCertificate = certificate.RawData;
            }

            var paX509 = new KrbPaS4uX509User
            {
                UserId = userId,
                Checksum = KrbChecksum.Create(userId.Encode(), sessionKey.AsKey(), (KeyUsage)26)
            };

            return paX509.Encode();
        }

        private static KrbApReq CreateApReq(KrbKdcRep kdcRep, KrbEncryptionKey tgtSessionKey, KrbChecksum checksum, out KrbEncryptionKey sessionKey)
        {
            var tgt = kdcRep.Ticket;

            var authenticator = new KrbAuthenticator
            {
                CName = kdcRep.CName,
                Realm = kdcRep.CRealm,
                SequenceNumber = GetNonce(),
                Checksum = checksum
            };

            sessionKey = KrbEncryptionKey.Generate(tgtSessionKey.EType);

            sessionKey.Usage = KeyUsage.EncTgsRepPartSubSessionKey;
            authenticator.Subkey = sessionKey;

            Now(out DateTimeOffset ctime, out int usec);

            authenticator.CTime = ctime;
            authenticator.CuSec = usec;

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
