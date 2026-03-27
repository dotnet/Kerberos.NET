// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;

namespace Kerberos.NET.Server
{
    /// <summary>
    /// Handles the PA-AS-FRESHNESS pre-authentication type as defined in RFC 8070.
    /// This provides a freshness token to PKINIT clients to prevent pre-play attacks.
    /// </summary>
    public class PaDataFreshnessHandler : KdcPreAuthenticationHandlerBase
    {
        public PaDataFreshnessHandler(IRealmService service)
            : base(service)
        {
        }

        /// <summary>
        /// After validation, include a PA-AS-FRESHNESS token in the response.
        /// The freshness token is an encrypted timestamp using the KDC key,
        /// allowing clients to prove their PKINIT request is fresh.
        /// </summary>
        public override void PostValidate(IKerberosPrincipal principal, List<KrbPaData> preAuthRequirements)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            if (preAuthRequirements == null)
            {
                throw new ArgumentNullException(nameof(preAuthRequirements));
            }

            var krbtgtName = KrbPrincipalName.WellKnown.Krbtgt(this.Service.Name);
            var krbtgtPrincipal = this.Service.Principals.Find(krbtgtName, this.Service.Name);

            if (krbtgtPrincipal == null)
            {
                return;
            }

            var kdcKey = krbtgtPrincipal.RetrieveLongTermCredential();

            var now = this.Service.Now();
            var timestamp = new KrbPaEncTsEnc { PaTimestamp = now, PaUSec = 0 };
            var encrypted = KrbEncryptedData.Encrypt(timestamp.Encode(), kdcKey, KeyUsage.PaEncTs);

            preAuthRequirements.Add(new KrbPaData
            {
                Type = PaDataType.PA_AS_FRESHNESS,
                Value = encrypted.Encode()
            });
        }

        /// <summary>
        /// Validates a freshness token received from a client by decrypting it
        /// with the KDC key and verifying the timestamp is within the allowed skew.
        /// </summary>
        /// <param name="tokenData">The encoded freshness token from the client</param>
        /// <param name="kdcKey">The KDC long-term key used to decrypt the token</param>
        /// <param name="skew">The maximum allowed clock skew</param>
        /// <param name="now">The current time</param>
        /// <returns>True if the token is valid and within the allowed time skew</returns>
        public static bool ValidateFreshnessToken(
            ReadOnlyMemory<byte> tokenData,
            KerberosKey kdcKey,
            TimeSpan skew,
            DateTimeOffset now)
        {
            try
            {
                var encrypted = KrbEncryptedData.Decode(tokenData);
                var decrypted = encrypted.Decrypt(kdcKey, KeyUsage.PaEncTs, b => KrbPaEncTsEnc.Decode(b));

                var diff = (now - decrypted.PaTimestamp).Duration();
                return diff <= skew;
            }
            catch
            {
                return false;
            }
        }
    }
}
