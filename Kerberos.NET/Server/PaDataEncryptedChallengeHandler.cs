// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Text;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using static Kerberos.NET.Entities.KerberosConstants;

namespace Kerberos.NET.Server
{
    /// <summary>
    /// Handles PA-ENCRYPTED-CHALLENGE pre-authentication within a FAST tunnel (RFC 6113 section 5.4.6).
    /// The encrypted challenge replaces the traditional encrypted timestamp when FAST is in use.
    /// </summary>
    public class PaDataEncryptedChallengeHandler : KdcPreAuthenticationHandlerBase
    {
        public PaDataEncryptedChallengeHandler(IRealmService service)
            : base(service)
        {
        }

        public override KrbPaData Validate(KrbKdcReq asReq, PreAuthenticationContext preauth)
        {
            if (asReq == null)
            {
                throw new ArgumentNullException(nameof(asReq));
            }

            if (preauth == null)
            {
                throw new ArgumentNullException(nameof(preauth));
            }

            if (preauth.PreAuthenticationSatisfied)
            {
                return null;
            }

            // Retrieve the FAST state; encrypted challenge requires an active FAST tunnel
            var fastState = preauth.GetState<FastState>(PaDataType.PA_FX_FAST);

            if (fastState.ArmorKey == null)
            {
                throw new KerberosProtocolException(
                    KerberosErrorCode.KDC_ERR_PREAUTH_FAILED,
                    "PA-ENCRYPTED-CHALLENGE requires FAST armor"
                );
            }

            // Find the encrypted challenge PA-Data
            var paChallenge = Array.Find(asReq.PaData, p => p.Type == PaDataType.PA_ENCRYPTED_CHALLENGE);

            if (paChallenge == null)
            {
                // Return a hint that encrypted challenge is expected
                return new KrbPaData
                {
                    Type = PaDataType.PA_ENCRYPTED_CHALLENGE
                };
            }

            var principal = preauth.Principal;
            var clientKey = principal.RetrieveLongTermCredential();
            var etype = fastState.ArmorKey.EncryptionType;

            // Derive the challenge key: CF2(armor_key, client_long_term_key, "clientchallengearmor", "challengelongterm")
            var challengeKeyBytes = KrbFx.Cf2(
                fastState.ArmorKey.GetKey().ToArray(),
                clientKey.GetKey().ToArray(),
                Encoding.UTF8.GetBytes("clientchallengearmor"),
                Encoding.UTF8.GetBytes("challengelongterm"),
                etype
            );

            var challengeKey = new KerberosKey(key: challengeKeyBytes.ToArray(), etype: etype);

            // Decrypt the challenge using the client challenge key
            var encData = KrbEncryptedData.Decode(paChallenge.Value);

            var timestamp = encData.Decrypt(
                challengeKey,
                KeyUsage.EncChallengeClient,
                b => KrbPaEncTsEnc.Decode(b)
            );

            // Validate the timestamp is within allowed skew
            var skew = this.Service.Settings.MaximumSkew;
            var now = this.Service.Now();

            if (!WithinSkew(now, timestamp.PaTimestamp, timestamp.PaUSec ?? 0, skew))
            {
                throw new KerberosValidationException(
                    $"Encrypted challenge timestamp is outside allowed skew. Timestamp: {timestamp.PaTimestamp}; Now: {now}; Skew: {skew}"
                );
            }

            // Build the KDC's encrypted challenge response
            Now(out DateTimeOffset kdcTime, out int kdcUsec);

            var kdcChallenge = new KrbPaEncTsEnc
            {
                PaTimestamp = kdcTime,
                PaUSec = kdcUsec
            };

            // Derive KDC challenge key (same derivation, but encrypted with KDC usage)
            var kdcChallengeKeyBytes = KrbFx.Cf2(
                fastState.ArmorKey.GetKey().ToArray(),
                clientKey.GetKey().ToArray(),
                Encoding.UTF8.GetBytes("kdcchallengearmor"),
                Encoding.UTF8.GetBytes("challengelongterm"),
                etype
            );

            var kdcChallengeKey = new KerberosKey(key: kdcChallengeKeyBytes.ToArray(), etype: etype);

            var encKdcChallenge = KrbEncryptedData.Encrypt(
                kdcChallenge.Encode(),
                kdcChallengeKey,
                KeyUsage.EncChallengeKdc
            );

            // Mark pre-auth satisfied with the client's long-term key
            preauth.EncryptedPartKey = clientKey;
            preauth.ClientAuthority = PaDataType.PA_ENCRYPTED_CHALLENGE;

            return new KrbPaData
            {
                Type = PaDataType.PA_ENCRYPTED_CHALLENGE,
                Value = encKdcChallenge.Encode()
            };
        }
    }
}
