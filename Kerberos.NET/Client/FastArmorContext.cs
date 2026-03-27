// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Linq;
using System.Text;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using static Kerberos.NET.Entities.KerberosConstants;

namespace Kerberos.NET.Client
{
    /// <summary>
    /// Manages FAST (RFC 6113) armor state for client-side AS-REQ armoring.
    /// Wraps outgoing requests in FAST armor and unwraps incoming FAST responses.
    /// </summary>
    public class FastArmorContext
    {
        /// <summary>
        /// The armor ticket (TGT) used to establish the FAST tunnel.
        /// </summary>
        public KrbKdcRep ArmorTgt { get; }

        /// <summary>
        /// The decrypted enc-part of the armor TGT providing the session key.
        /// </summary>
        public KrbEncKdcRepPart ArmorTgtEncPart { get; }

        /// <summary>
        /// The derived FAST armor key protecting the tunnel.
        /// </summary>
        public KerberosKey ArmorKey { get; private set; }

        /// <summary>
        /// The authenticator subkey used in the armor AP-REQ.
        /// </summary>
        private KrbEncryptionKey subkey;

        public FastArmorContext(KrbKdcRep armorTgt, KrbEncKdcRepPart armorTgtEncPart)
        {
            this.ArmorTgt = armorTgt ?? throw new ArgumentNullException(nameof(armorTgt));
            this.ArmorTgtEncPart = armorTgtEncPart ?? throw new ArgumentNullException(nameof(armorTgtEncPart));
        }

        /// <summary>
        /// Wraps a KDC request in FAST armor, returning the modified request
        /// with PA_FX_FAST PA-Data added.
        /// </summary>
        public KrbAsReq WrapRequest(KrbAsReq asReq)
        {
            if (asReq == null)
            {
                throw new ArgumentNullException(nameof(asReq));
            }

            var sessionKey = this.ArmorTgtEncPart.Key;
            var etype = sessionKey.EType;

            // Generate a subkey for the armor AP-REQ
            this.subkey = KrbEncryptionKey.Generate(etype);

            // Create the armor AP-REQ using the armor TGT
            Now(out DateTimeOffset ctime, out int cusec);

            var authenticator = new KrbAuthenticator
            {
                CName = this.ArmorTgt.CName,
                CRealm = this.ArmorTgt.CRealm,
                CTime = ctime,
                CuSec = cusec,
                SequenceNumber = GetNonce(),
                Subkey = this.subkey
            };

            var armorApReq = new KrbApReq
            {
                Ticket = this.ArmorTgt.Ticket,
                Authenticator = KrbEncryptedData.Encrypt(
                    authenticator.EncodeApplication(),
                    sessionKey.AsKey(),
                    KeyUsage.ApReqAuthenticator
                )
            };

            // Derive the armor key: CF2(subkey, ticket_session_key, "subkeyarmor", "ticketarmor")
            var armorKeyBytes = KrbFx.Cf2(
                this.subkey.KeyValue.ToArray(),
                sessionKey.KeyValue.ToArray(),
                Encoding.UTF8.GetBytes("subkeyarmor"),
                Encoding.UTF8.GetBytes("ticketarmor"),
                etype
            );

            this.ArmorKey = new KerberosKey(key: armorKeyBytes.ToArray(), etype: etype);

            // Build the inner FAST request with the original PA-Data and req-body
            var fastReq = new KrbFastReq
            {
                FastOptions = FastOptions.Reserved,
                PaData = asReq.PaData ?? Array.Empty<KrbPaData>(),
                ReqBody = asReq.Body
            };

            // Compute the checksum over the outer KDC-REQ-BODY
            var outerBodyEncoded = asReq.Body.Encode();
            var requestChecksum = KrbChecksum.Create(outerBodyEncoded, this.ArmorKey, KeyUsage.FastReqChecksum);

            // Encrypt the inner FAST request
            var encFastReq = KrbEncryptedData.Encrypt(
                fastReq.Encode(),
                this.ArmorKey,
                KeyUsage.FastEnc
            );

            // Build the armored request
            var armoredReq = new KrbFastArmoredReq
            {
                Armor = new KrbFastArmor
                {
                    Type = KrbArmorType.FX_FAST_ARMOR_AP_REQUEST,
                    Value = armorApReq.EncodeApplication()
                },
                RequestChecksum = requestChecksum,
                EncryptedFastRequest = encFastReq
            };

            var fastRequest = new KrbPaFxFastRequest
            {
                ArmoredData = armoredReq
            };

            // Add PA_FX_FAST to the outer request's PA-Data
            var outerPaData = new[]
            {
                new KrbPaData
                {
                    Type = PaDataType.PA_FX_FAST,
                    Value = fastRequest.Encode()
                }
            };

            return new KrbAsReq
            {
                Body = asReq.Body,
                PaData = outerPaData,
                MessageType = asReq.MessageType,
                ProtocolVersionNumber = asReq.ProtocolVersionNumber
            };
        }

        /// <summary>
        /// Unwraps a FAST response from an AS-REP, extracting the inner PA-Data
        /// and applying the strengthen key to the reply key.
        /// </summary>
        /// <param name="asRep">The AS-REP containing FAST PA-Data</param>
        /// <param name="replyKey">The reply key to strengthen; will be replaced with the strengthened key</param>
        /// <returns>The FAST response containing inner PA-Data and finished message</returns>
        public KrbFastResponse UnwrapResponse(KrbAsRep asRep, ref KerberosKey replyKey)
        {
            if (asRep == null)
            {
                throw new ArgumentNullException(nameof(asRep));
            }

            if (this.ArmorKey == null)
            {
                throw new InvalidOperationException("Armor key has not been established. Call WrapRequest first.");
            }

            var paFast = asRep.PaData?.FirstOrDefault(p => p.Type == PaDataType.PA_FX_FAST);

            if (paFast == null)
            {
                return null;
            }

            var fastReply = KrbPaFxFastReply.Decode(paFast.Value);
            var armoredRep = fastReply.ArmoredData;

            // Decrypt the FAST response using the armor key
            var fastResponse = armoredRep.EncFastRep.Decrypt(
                this.ArmorKey,
                KeyUsage.FastRep,
                b => KrbFastResponse.Decode(b)
            );

            // Strengthen the reply key if a strengthen key is present
            if (fastResponse.StrengthenKey != null && replyKey != null)
            {
                var etype = this.ArmorKey.EncryptionType;

                var strengthenedKeyBytes = KrbFx.Cf2(
                    replyKey.GetKey().ToArray(),
                    fastResponse.StrengthenKey.KeyValue.ToArray(),
                    Encoding.UTF8.GetBytes("strengthenkey"),
                    Encoding.UTF8.GetBytes("replykey"),
                    etype
                );

                replyKey = new KerberosKey(key: strengthenedKeyBytes.ToArray(), etype: etype);
            }

            return fastResponse;
        }

        /// <summary>
        /// Extracts FAST error response from a KRB-ERROR when FAST is active.
        /// </summary>
        public KrbFastResponse UnwrapError(KrbError error)
        {
            if (error?.EData == null || this.ArmorKey == null)
            {
                return null;
            }

            try
            {
                var methodData = KrbMethodData.Decode(error.EData.Value);

                var paFast = methodData.MethodData?.FirstOrDefault(p => p.Type == PaDataType.PA_FX_FAST);

                if (paFast == null)
                {
                    return null;
                }

                var fastReply = KrbPaFxFastReply.Decode(paFast.Value);
                var armoredRep = fastReply.ArmoredData;

                return armoredRep.EncFastRep.Decrypt(
                    this.ArmorKey,
                    KeyUsage.FastRep,
                    b => KrbFastResponse.Decode(b)
                );
            }
            catch
            {
                // If we can't parse the FAST error, fall through to normal error handling
                return null;
            }
        }
    }
}
