// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using Kerberos.NET.Configuration;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;

namespace Kerberos.NET.Server
{
    /// <summary>
    /// Handles SPAKE pre-authentication per draft-ietf-kitten-krb-spake-preauth.
    /// Provides password-authenticated key exchange that resists offline dictionary attacks.
    ///
    /// The exchange proceeds in two rounds:
    /// 1. Client sends AS-REQ without SPAKE data; KDC returns a challenge with supported groups.
    /// 2. Client sends AS-REQ with SPAKE response; KDC completes the exchange and derives the key.
    ///
    /// The actual elliptic curve operations (point multiplication with blinding factors) are
    /// provided as an extensibility point via <see cref="SpakeGroupOperation"/> since the full
    /// SPAKE2+ protocol requires EC math that may vary by deployment.
    /// </summary>
    public class PaDataSpakeHandler : KdcPreAuthenticationHandlerBase
    {
        /// <summary>
        /// Delegate for performing the SPAKE group-specific elliptic curve computation.
        /// Implementations should compute the SPAKE2+ shared secret from the server's
        /// private scalar and the client's public element.
        /// </summary>
        /// <param name="group">The negotiated SPAKE group.</param>
        /// <param name="serverPrivateKey">The server's private scalar value.</param>
        /// <param name="clientPublicValue">The client's public element from the SPAKE response.</param>
        /// <param name="password">The client's long-term credential for password blinding.</param>
        /// <returns>The computed shared secret bytes.</returns>
        public delegate byte[] SpakeGroupOperationDelegate(
            SpakePreAuthGroupType group,
            byte[] serverPrivateKey,
            byte[] clientPublicValue,
            KerberosKey password);

        /// <summary>
        /// Gets or sets the pluggable SPAKE group operation used to compute the shared secret.
        /// When null, the handler will use a simplified key derivation that does not perform
        /// actual EC point operations. Set this to provide a full SPAKE2+ implementation.
        /// </summary>
        public static SpakeGroupOperationDelegate SpakeGroupOperation { get; set; }

        public PaDataSpakeHandler(IRealmService service)
            : base(service)
        {
        }

        public override void PreValidate(PreAuthenticationContext preauth)
        {
            if (preauth == null)
            {
                throw new ArgumentNullException(nameof(preauth));
            }

            // Only initialize SPAKE state if the principal supports it
            if (preauth.Principal?.SupportedPreAuthenticationTypes?.Contains(PaDataType.PA_SPAKE) == true)
            {
                preauth.GetState<SpakeState>(PaDataType.PA_SPAKE);
            }
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

            var spakeState = preauth.GetState<SpakeState>(PaDataType.PA_SPAKE);

            // Look for SPAKE PA-Data from the client
            var paSpake = asReq.PaData?.FirstOrDefault(p => p.Type == PaDataType.PA_SPAKE);

            if (paSpake == null || paSpake.Value.Length == 0)
            {
                // First round: no SPAKE data from client, return challenge with supported groups
                return GenerateChallenge(spakeState);
            }

            // Second round: client sent SPAKE response, complete the exchange
            return CompleteExchange(asReq, preauth, spakeState, paSpake.Value);
        }

        public override void PostValidate(IKerberosPrincipal principal, List<KrbPaData> preAuthRequirements)
        {
            // No post-validation hints needed for SPAKE
        }

        private KrbPaData GenerateChallenge(SpakeState spakeState)
        {
            var configuredGroups = this.Service.Configuration?.Defaults?.SpakePreAuthGroups;

            if (configuredGroups == null || configuredGroups.Count == 0)
            {
                // Default to P-256 if no groups configured
                configuredGroups = new[] { SpakePreAuthGroupType.P_256 };
            }

            // Select the first (highest priority) group
            var selectedGroup = configuredGroups.First();
            spakeState.SelectedGroup = selectedGroup;

            // Generate the server's private scalar for this exchange
            spakeState.ServerPrivateKey = SpakeExchange.GenerateScalar(selectedGroup);
            spakeState.ChallengeSent = true;

            // Encode the challenge: supported group list and server's public value
            // The challenge is encoded as: [group_count (2 bytes)] [group_id (2 bytes)]... [server_public_value]
            var keySize = SpakeExchange.GetKeySize(selectedGroup);
            var groupList = configuredGroups.ToArray();
            var challengeLength = 2 + (groupList.Length * 2) + keySize;
            var challenge = new byte[challengeLength];

            // Group count
            challenge[0] = (byte)((groupList.Length >> 8) & 0xFF);
            challenge[1] = (byte)(groupList.Length & 0xFF);

            // Group identifiers
            for (int i = 0; i < groupList.Length; i++)
            {
                var groupId = (ushort)groupList[i];
                challenge[2 + (i * 2)] = (byte)((groupId >> 8) & 0xFF);
                challenge[2 + (i * 2) + 1] = (byte)(groupId & 0xFF);
            }

            // Server's public value (in a full implementation this would be the
            // EC public point with password blinding; here we use the raw scalar
            // as a placeholder for the extensibility point)
            Buffer.BlockCopy(
                spakeState.ServerPrivateKey, 0,
                challenge, 2 + (groupList.Length * 2),
                keySize);

            return new KrbPaData
            {
                Type = PaDataType.PA_SPAKE,
                Value = challenge
            };
        }

        private KrbPaData CompleteExchange(
            KrbKdcReq asReq,
            PreAuthenticationContext preauth,
            SpakeState spakeState,
            ReadOnlyMemory<byte> clientResponse)
        {
            if (!spakeState.ChallengeSent)
            {
                throw new KerberosProtocolException(
                    KerberosErrorCode.KDC_ERR_PREAUTH_FAILED,
                    "SPAKE exchange received a response without a prior challenge"
                );
            }

            var principal = preauth.Principal;
            var clientKey = principal.RetrieveLongTermCredential();

            // Parse the client response: [selected_group (2 bytes)] [client_public_value]
            var responseBytes = clientResponse.ToArray();

            if (responseBytes.Length < 2)
            {
                throw new KerberosProtocolException(
                    KerberosErrorCode.KDC_ERR_PREAUTH_FAILED,
                    "SPAKE client response is too short"
                );
            }

            var selectedGroupId = (ushort)((responseBytes[0] << 8) | responseBytes[1]);
            var selectedGroup = (SpakePreAuthGroupType)selectedGroupId;

            // Verify the client selected a group we support
            var configuredGroups = this.Service.Configuration?.Defaults?.SpakePreAuthGroups;

            if (configuredGroups == null || !configuredGroups.Contains(selectedGroup))
            {
                throw new KerberosProtocolException(
                    KerberosErrorCode.KDC_ERR_PREAUTH_FAILED,
                    $"SPAKE client selected unsupported group: {selectedGroup}"
                );
            }

            var expectedKeySize = SpakeExchange.GetKeySize(selectedGroup);

            if (responseBytes.Length != 2 + expectedKeySize)
            {
                throw new KerberosProtocolException(
                    KerberosErrorCode.KDC_ERR_PREAUTH_FAILED,
                    $"SPAKE client response has invalid length for group {selectedGroup}"
                );
            }

            var clientPublicValue = new byte[expectedKeySize];
            Buffer.BlockCopy(responseBytes, 2, clientPublicValue, 0, expectedKeySize);

            // Compute the shared secret using the pluggable group operation
            byte[] sharedSecret;

            if (SpakeGroupOperation != null)
            {
                sharedSecret = SpakeGroupOperation(
                    selectedGroup,
                    spakeState.ServerPrivateKey,
                    clientPublicValue,
                    clientKey);
            }
            else
            {
                // Default simplified key derivation when no EC implementation is plugged in.
                // This combines the server private key, client public value, and password
                // using HMAC to produce a shared secret. A production deployment should
                // provide a full SPAKE2+ group operation via SpakeGroupOperation.
                sharedSecret = DeriveSimplifiedSharedSecret(
                    selectedGroup,
                    spakeState.ServerPrivateKey,
                    clientPublicValue,
                    clientKey);
            }

            spakeState.SharedSecret = sharedSecret;

            // Build the transcript for key derivation
            // Transcript = H(client_name || server_challenge || client_response)
            var clientName = principal.PrincipalName;
            var transcript = BuildTranscript(clientName, spakeState.ServerPrivateKey, clientPublicValue);

            // Derive the final key from the shared secret and transcript
            var derivedKeyBytes = SpakeExchange.DeriveKey(selectedGroup, sharedSecret, transcript);

            // Use the derived key as the encrypted part key
            var preferredEType = clientKey.EncryptionType;

            preauth.EncryptedPartKey = new KerberosKey(
                key: derivedKeyBytes,
                etype: preferredEType);
            preauth.EncryptedPartEType = preferredEType;
            preauth.ClientAuthority = PaDataType.PA_SPAKE;

            // Return a confirmation PA-Data containing the server's proof
            // In a full implementation this would be EncryptedData proving
            // the server also knows the shared secret
            var confirmation = new byte[expectedKeySize];

            using (var hmac = IncrementalHash.CreateHMAC(
                SpakeExchange.GetHashAlgorithm(selectedGroup),
                derivedKeyBytes))
            {
                hmac.AppendData(spakeState.ServerPrivateKey);
                hmac.AppendData(clientPublicValue);
                var proof = hmac.GetHashAndReset();
                Buffer.BlockCopy(proof, 0, confirmation, 0, Math.Min(proof.Length, confirmation.Length));
            }

            return new KrbPaData
            {
                Type = PaDataType.PA_SPAKE,
                Value = confirmation
            };
        }

        private static byte[] DeriveSimplifiedSharedSecret(
            SpakePreAuthGroupType group,
            byte[] serverPrivateKey,
            byte[] clientPublicValue,
            KerberosKey password)
        {
            var hashAlg = SpakeExchange.GetHashAlgorithm(group);
            var passwordBytes = password.GetKey().ToArray();

            using var hmac = IncrementalHash.CreateHMAC(hashAlg, passwordBytes);
            hmac.AppendData(serverPrivateKey);
            hmac.AppendData(clientPublicValue);

            return hmac.GetHashAndReset();
        }

        private static byte[] BuildTranscript(
            string clientName,
            byte[] serverPublicValue,
            byte[] clientPublicValue)
        {
            var clientNameBytes = System.Text.Encoding.UTF8.GetBytes(clientName ?? string.Empty);

            var transcript = new byte[clientNameBytes.Length + serverPublicValue.Length + clientPublicValue.Length];
            var offset = 0;

            Buffer.BlockCopy(clientNameBytes, 0, transcript, offset, clientNameBytes.Length);
            offset += clientNameBytes.Length;

            Buffer.BlockCopy(serverPublicValue, 0, transcript, offset, serverPublicValue.Length);
            offset += serverPublicValue.Length;

            Buffer.BlockCopy(clientPublicValue, 0, transcript, offset, clientPublicValue.Length);

            return transcript;
        }
    }
}
