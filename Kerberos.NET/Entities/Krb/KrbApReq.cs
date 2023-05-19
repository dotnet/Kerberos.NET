// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Asn1;
using Kerberos.NET.Asn1;
using Kerberos.NET.Crypto;
using static Kerberos.NET.Entities.KerberosConstants;

namespace Kerberos.NET.Entities
{
    public partial class KrbApReq : IAsn1ApplicationEncoder<KrbApReq>
    {
        internal const int ApplicationTagValue = 14;

        private static readonly Oid Kerberos5Oid = new(MechType.KerberosV5);
        private static readonly Oid SPNegoOid = new(MechType.SPNEGO);

        public KrbApReq()
        {
            this.ProtocolVersionNumber = 5;
            this.MessageType = MessageType.KRB_AP_REQ;
        }

        public static bool CanDecode(ReadOnlyMemory<byte> encoded)
        {
            var reader = new AsnReader(encoded, AsnEncodingRules.DER);

            var tag = reader.ReadTagAndLength(out _, out _);

            return tag.HasSameClassAndValue(ApplicationTag);
        }

        public KrbApReq DecodeAsApplication(ReadOnlyMemory<byte> data)
        {
            return DecodeApplication(data);
        }

        public static KrbApReq CreateApReq(
            KrbKdcRep tgsRep,
            KerberosKey authenticatorKey,
            RequestServiceTicket rst,
            out KrbAuthenticator authenticator
        )
        {
            if (tgsRep == null)
            {
                throw new ArgumentNullException(nameof(tgsRep));
            }

            if (authenticatorKey == null)
            {
                throw new ArgumentNullException(nameof(authenticatorKey));
            }

            authenticator = new KrbAuthenticator
            {
                CName = tgsRep.CName,
                Realm = tgsRep.CRealm
            };

            if (rst.AuthenticatorChecksum != null)
            {
                authenticator.Checksum = rst.AuthenticatorChecksum;
            }
            else if (!rst.AuthenticatorChecksumSource.IsEmpty)
            {
                authenticator.Checksum = KrbChecksum.Create(
                    rst.AuthenticatorChecksumSource,
                    authenticatorKey,
                    KeyUsage.AuthenticatorChecksum
                );
            }
            else if (rst.GssContextFlags != GssContextEstablishmentFlag.GSS_C_NONE)
            {
                authenticator.Checksum = KrbChecksum.EncodeDelegationChecksum(new DelegationInfo(rst));
            }

            if (rst.IncludeSequenceNumber ?? true)
            {
                authenticator.SequenceNumber = GetNonce();
            }

            if (rst.ApOptions.HasFlag(ApOptions.MutualRequired))
            {
                authenticator.Subkey = KrbEncryptionKey.Generate(authenticatorKey.EncryptionType);
            }

            Now(out DateTimeOffset ctime, out int usec);

            authenticator.CTime = ctime;
            authenticator.CuSec = usec;

            var apReq = new KrbApReq
            {
                Ticket = tgsRep.Ticket,
                ApOptions = rst.ApOptions,
                Authenticator = KrbEncryptedData.Encrypt(
                    authenticator.EncodeApplication(),
                    authenticatorKey,
                    KeyUsage.ApReqAuthenticator
                )
            };

            return apReq;
        }

        public ReadOnlyMemory<byte> EncodeGssApi()
        {
            var token = GssApiToken.Encode(Kerberos5Oid, this);

            var negoToken = new NegotiationToken
            {
                InitialToken = new NegTokenInit
                {
                    MechTypes = new[] { Kerberos5Oid },
                    MechToken = token
                }
            };

            return GssApiToken.Encode(SPNegoOid, negoToken);
        }
    }
}
