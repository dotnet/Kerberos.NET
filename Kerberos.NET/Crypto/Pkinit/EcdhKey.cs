// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;

namespace Kerberos.NET.Crypto
{
    /// <summary>
    /// Represents an elliptic curve Diffie-Hellman key for PKINIT.
    /// The public component is the uncompressed EC point (04 || x || y).
    /// </summary>
    public class EcdhKey : IExchangeKey
    {
        public AsymmetricKeyType Type { get; set; }

        public KeyAgreementAlgorithm Algorithm { get; set; }

        public DateTimeOffset? CacheExpiry { get; set; }

        public int KeyLength { get; set; }

        public ReadOnlyMemory<byte> PublicComponent { get; set; }

        public ReadOnlyMemory<byte> PrivateComponent { get; set; }

        /// <summary>
        /// For ECDH in PKINIT, the SubjectPublicKey is the raw uncompressed EC point
        /// encoded as a BIT STRING value. Per RFC 5480, the public key is just the
        /// uncompressed point (04 || x || y).
        /// </summary>
        public ReadOnlyMemory<byte> EncodePublicKey()
        {
            return this.PublicComponent;
        }

        /// <summary>
        /// Parse an EC public key from the SubjectPublicKey BIT STRING value.
        /// The value is an uncompressed point (04 || x || y).
        /// </summary>
        public static EcdhKey ParsePublicKey(ReadOnlyMemory<byte> data, KeyAgreementAlgorithm algorithm)
        {
            var keyData = data;

            // The SubjectPublicKey may have the uncompressed point directly
            // or may be wrapped. We expect the uncompressed format: 04 || x || y
            if (keyData.Length > 0 && keyData.Span[0] == 0x04)
            {
                // Already in uncompressed format
            }
            else if (keyData.Length > 1 && keyData.Span[0] == 0x00)
            {
                // BIT STRING padding byte
                keyData = keyData.Slice(1);
            }

            int coordinateSize = algorithm switch
            {
                KeyAgreementAlgorithm.EllipticCurveDiffieHellmanP256 => 32,
                KeyAgreementAlgorithm.EllipticCurveDiffieHellmanP384 => 48,
                KeyAgreementAlgorithm.EllipticCurveDiffieHellmanP521 => 66,
                _ => throw new ArgumentException($"Unsupported EC algorithm: {algorithm}")
            };

            return new EcdhKey
            {
                Algorithm = algorithm,
                Type = AsymmetricKeyType.Public,
                KeyLength = coordinateSize,
                PublicComponent = keyData.ToArray()
            };
        }
    }
}
