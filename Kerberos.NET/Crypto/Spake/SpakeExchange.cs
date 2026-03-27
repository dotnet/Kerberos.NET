// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Security.Cryptography;
using Kerberos.NET.Configuration;

namespace Kerberos.NET.Crypto
{
    /// <summary>
    /// Implements the SPAKE2+ password-authenticated key exchange for Kerberos
    /// pre-authentication per draft-ietf-kitten-krb-spake-preauth.
    /// </summary>
    public static class SpakeExchange
    {
        /// <summary>
        /// Get the key size in bytes for the given SPAKE group.
        /// </summary>
        public static int GetKeySize(SpakePreAuthGroupType group)
        {
            return group switch
            {
                SpakePreAuthGroupType.Edwards25519 => 32,
                SpakePreAuthGroupType.P_256 => 32,
                SpakePreAuthGroupType.P_384 => 48,
                SpakePreAuthGroupType.P_521 => 66,
                _ => throw new ArgumentOutOfRangeException(nameof(group))
            };
        }

        /// <summary>
        /// Get the hash algorithm for the given SPAKE group.
        /// </summary>
        public static HashAlgorithmName GetHashAlgorithm(SpakePreAuthGroupType group)
        {
            return group switch
            {
                SpakePreAuthGroupType.Edwards25519 => HashAlgorithmName.SHA256,
                SpakePreAuthGroupType.P_256 => HashAlgorithmName.SHA256,
                SpakePreAuthGroupType.P_384 => HashAlgorithmName.SHA384,
                SpakePreAuthGroupType.P_521 => HashAlgorithmName.SHA512,
                _ => throw new ArgumentOutOfRangeException(nameof(group))
            };
        }

        /// <summary>
        /// Generate a random scalar value for the SPAKE exchange.
        /// </summary>
        public static byte[] GenerateScalar(SpakePreAuthGroupType group)
        {
            var keySize = GetKeySize(group);
            var scalar = new byte[keySize];

            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(scalar);

            return scalar;
        }

        /// <summary>
        /// Derive the SPAKE pre-authentication key from the shared secret
        /// using the transcript hash per the draft specification.
        /// </summary>
        public static byte[] DeriveKey(
            SpakePreAuthGroupType group,
            byte[] sharedSecret,
            byte[] transcript)
        {
            if (sharedSecret == null)
            {
                throw new ArgumentNullException(nameof(sharedSecret));
            }

            if (transcript == null)
            {
                throw new ArgumentNullException(nameof(transcript));
            }

            var hashAlg = GetHashAlgorithm(group);
            var keySize = GetKeySize(group);

            // K' = HMAC(transcript_hash, shared_secret)
            // The actual key derivation is: K = KDF(K', "SPAKEKey")

            using var hash = IncrementalHash.CreateHash(hashAlg);
            hash.AppendData(transcript);
            var transcriptHash = hash.GetHashAndReset();

            using var hmac = IncrementalHash.CreateHMAC(hashAlg, transcriptHash);
            hmac.AppendData(sharedSecret);
            var derived = hmac.GetHashAndReset();

            // Truncate to key size if needed
            if (derived.Length > keySize)
            {
                var truncated = new byte[keySize];
                Buffer.BlockCopy(derived, 0, truncated, 0, keySize);
                return truncated;
            }

            return derived;
        }
    }
}
