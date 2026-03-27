// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using static Kerberos.NET.Entities.KerberosConstants;

namespace Kerberos.NET.Server
{
    /// <summary>
    /// Handles FAST (RFC 6113) armored pre-authentication for the KDC.
    /// This handler unwraps FAST-armored requests during PreValidate and
    /// wraps responses during PostValidate.
    /// </summary>
    public class PaDataFastHandler : KdcPreAuthenticationHandlerBase
    {
        public PaDataFastHandler(IRealmService service)
            : base(service)
        {
        }

        /// <summary>
        /// Unwraps the FAST armor from the request, derives the armor key,
        /// verifies the request checksum, and decrypts the inner FAST request.
        /// </summary>
        public override void PreValidate(PreAuthenticationContext preauth)
        {
            if (preauth == null)
            {
                throw new ArgumentNullException(nameof(preauth));
            }

            var asReq = (KrbKdcReq)preauth.Message;

            if (asReq.PaData == null)
            {
                return;
            }

            var paFast = asReq.PaData.FirstOrDefault(p => p.Type == PaDataType.PA_FX_FAST);

            if (paFast == null)
            {
                return;
            }

            var state = preauth.GetState<FastState>(PaDataType.PA_FX_FAST);

            // Decode PA-FX-FAST-REQUEST -> KrbFastArmoredReq
            var fastRequest = KrbPaFxFastRequest.Decode(paFast.Value);
            var armoredReq = fastRequest.ArmoredData;

            if (armoredReq == null)
            {
                throw new KerberosProtocolException(
                    KerberosErrorCode.KDC_ERR_PREAUTH_FAILED,
                    "FAST armored request is missing armored data"
                );
            }

            // The armor field MUST be present in AS-REQ
            if (armoredReq.Armor == null)
            {
                throw new KerberosProtocolException(
                    KerberosErrorCode.KDC_ERR_PREAUTH_FAILED,
                    "FAST armor is required for AS-REQ"
                );
            }

            if (armoredReq.Armor.Type != KrbArmorType.FX_FAST_ARMOR_AP_REQUEST)
            {
                throw new KerberosProtocolException(
                    KerberosErrorCode.KDC_ERR_PREAUTH_FAILED,
                    $"Unsupported FAST armor type: {armoredReq.Armor.Type}"
                );
            }

            // Decrypt the armor AP-REQ to obtain the armor ticket session key
            var armorApReq = KrbApReq.DecodeApplication(armoredReq.Armor.Value.Value);
            var decryptedArmorApReq = DecryptArmorApReq(armorApReq);

            state.DecryptedArmorApReq = decryptedArmorApReq;

            // Derive the armor key per RFC 6113 section 5.4.2:
            // armor_key = CF2(subkey, ticket_session_key, "subkeyarmor", "ticketarmor")
            var subkey = decryptedArmorApReq.Authenticator.Subkey
                ?? throw new KerberosProtocolException(
                    KerberosErrorCode.KDC_ERR_PREAUTH_FAILED,
                    "FAST armor AP-REQ must contain an authenticator subkey"
                );

            var ticketSessionKey = decryptedArmorApReq.Ticket.Key;
            var etype = subkey.EType;

            var armorKeyBytes = KrbFx.Cf2(
                subkey.KeyValue.ToArray(),
                ticketSessionKey.KeyValue.ToArray(),
                Encoding.UTF8.GetBytes("subkeyarmor"),
                Encoding.UTF8.GetBytes("ticketarmor"),
                etype
            );

            var armorKey = new KerberosKey(key: armorKeyBytes.ToArray(), etype: etype);
            state.ArmorKey = armorKey;

            // Verify the request checksum over the outer KDC-REQ-BODY
            var outerBodyEncoded = asReq.Body.Encode();

            var checksumType = CryptoService.ConvertType(armorKey.EncryptionType);
            var checksumValidator = CryptoService.CreateChecksum(
                checksumType,
                armoredReq.RequestChecksum.Checksum,
                outerBodyEncoded
            );

            checksumValidator.Usage = KeyUsage.FastReqChecksum;
            checksumValidator.Validate(armorKey);

            // Decrypt the inner FAST request
            var innerRequest = armoredReq.EncryptedFastRequest.Decrypt(
                armorKey,
                KeyUsage.FastEnc,
                b => KrbFastReq.Decode(b)
            );

            state.InnerRequest = innerRequest;
        }

        /// <summary>
        /// Builds the FAST response, strengthens the reply key, and wraps
        /// the response PA-Data in a FAST armored reply.
        /// </summary>
        public override void PostValidate(IKerberosPrincipal principal, List<KrbPaData> preAuthRequirements)
        {
            // PostValidate doesn't have direct access to PreAuthenticationContext,
            // so FAST response wrapping is handled in KdcAsReqMessageHandler instead.
            // This method is intentionally left empty.
        }

        private DecryptedKrbApReq DecryptArmorApReq(KrbApReq armorApReq)
        {
            // The armor AP-REQ uses a TGT. We need to find the krbtgt key to decrypt it.
            var krbtgtIdentity = this.Service.Principals.Find(armorApReq.Ticket.SName, armorApReq.Ticket.Realm);

            if (krbtgtIdentity == null)
            {
                throw new KerberosProtocolException(
                    KerberosErrorCode.KDC_ERR_S_PRINCIPAL_UNKNOWN,
                    "Cannot find the service principal for the FAST armor ticket"
                );
            }

            var krbtgtKey = krbtgtIdentity.RetrieveLongTermCredential();

            if (krbtgtKey == null)
            {
                throw new KerberosProtocolException(
                    KerberosErrorCode.KDC_ERR_ETYPE_NOSUPP,
                    "Cannot retrieve the key for the FAST armor ticket service"
                );
            }

            var decrypted = new DecryptedKrbApReq(armorApReq);

            decrypted.Decrypt(krbtgtKey);

            decrypted.Validate(ValidationActions.All & ~ValidationActions.Replay & ~ValidationActions.ChannelBinding);

            return decrypted;
        }

        /// <summary>
        /// Creates the FAST response wrapping for an AS-REP or error.
        /// Called from the message handler after the reply is generated.
        /// </summary>
        public static KrbPaData WrapFastResponse(
            FastState state,
            KrbPaData[] innerPaData,
            KrbKdcRep rep,
            PreAuthenticationContext preauth)
        {
            if (state?.ArmorKey == null)
            {
                return null;
            }

            var etype = state.ArmorKey.EncryptionType;

            // Generate a random strengthen key
            var strengthenKeyData = KrbEncryptionKey.Generate(etype);
            state.StrengthenKey = strengthenKeyData.AsKey();

            // Strengthen the reply key: CF2(reply_key, strengthen_key, "strengthenkey", "replykey")
            if (preauth.EncryptedPartKey != null)
            {
                var strengthenedKeyBytes = KrbFx.Cf2(
                    preauth.EncryptedPartKey.GetKey().ToArray(),
                    state.StrengthenKey.GetKey().ToArray(),
                    Encoding.UTF8.GetBytes("strengthenkey"),
                    Encoding.UTF8.GetBytes("replykey"),
                    etype
                );

                preauth.EncryptedPartKey = new KerberosKey(key: strengthenedKeyBytes.ToArray(), etype: etype);
            }

            // Build KrbFastFinished with ticket checksum
            KrbFastFinished finished = null;

            if (rep != null)
            {
                Now(out DateTimeOffset timestamp, out int usec);

                finished = new KrbFastFinished
                {
                    Timestamp = timestamp,
                    USec = usec,
                    CRealm = rep.CRealm,
                    CName = rep.CName,
                    TicketChecksum = KrbChecksum.Create(
                        rep.Ticket.EncodeApplication(),
                        state.ArmorKey,
                        KeyUsage.FastFinished
                    )
                };
            }

            // Build the FAST response
            var fastResponse = new KrbFastResponse
            {
                PaData = innerPaData ?? Array.Empty<KrbPaData>(),
                StrengthenKey = strengthenKeyData,
                Finished = finished,
                Nonce = state.InnerRequest?.ReqBody?.Nonce ?? 0
            };

            // Encrypt the FAST response with the armor key
            var encFastRep = KrbEncryptedData.Encrypt(
                fastResponse.Encode(),
                state.ArmorKey,
                KeyUsage.FastRep
            );

            var armoredRep = new KrbFastArmoredRep
            {
                EncFastRep = encFastRep
            };

            var fastReply = new KrbPaFxFastReply
            {
                ArmoredData = armoredRep
            };

            return new KrbPaData
            {
                Type = PaDataType.PA_FX_FAST,
                Value = fastReply.Encode()
            };
        }

        /// <summary>
        /// Wraps an error response in PA_FX_ERROR when FAST is active.
        /// </summary>
        public static KrbPaData WrapFastError(FastState state, KrbError error)
        {
            if (state?.ArmorKey == null || error == null)
            {
                return null;
            }

            var fastResponse = new KrbFastResponse
            {
                PaData = new[]
                {
                    new KrbPaData
                    {
                        Type = PaDataType.PA_FX_ERROR,
                        Value = error.EncodeApplication()
                    }
                },
                Nonce = state.InnerRequest?.ReqBody?.Nonce ?? 0
            };

            var encFastRep = KrbEncryptedData.Encrypt(
                fastResponse.Encode(),
                state.ArmorKey,
                KeyUsage.FastRep
            );

            var armoredRep = new KrbFastArmoredRep
            {
                EncFastRep = encFastRep
            };

            var fastReply = new KrbPaFxFastReply
            {
                ArmoredData = armoredRep
            };

            return new KrbPaData
            {
                Type = PaDataType.PA_FX_FAST,
                Value = fastReply.Encode()
            };
        }
    }
}
