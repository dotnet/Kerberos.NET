// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using Kerberos.NET.Crypto;

namespace Kerberos.NET.Entities
{
    /// <summary>
    /// Containers Authenticated by Multiple MACs per RFC 7751.
    /// Provides integrity protection for authorization data across
    /// realm boundaries using KDC and service verifier MACs.
    /// Encode/Decode methods are provided by the generated partial class.
    /// </summary>
    public partial class KrbAdCammac
    {
        /// <summary>
        /// Create a CAMMAC wrapping the given authorization data with KDC and service verifiers.
        /// </summary>
        /// <param name="elements">The authorization data elements to protect.</param>
        /// <param name="kdcKey">The KDC key used to create the KDC verifier MAC.</param>
        /// <param name="serviceKey">Optional service key used to create the service verifier MAC.</param>
        /// <returns>A new CAMMAC instance with computed verifier MACs.</returns>
        public static KrbAdCammac Create(
            KrbAuthorizationData[] elements,
            KerberosKey kdcKey,
            KerberosKey serviceKey = null)
        {
            if (elements == null)
            {
                throw new ArgumentNullException(nameof(elements));
            }

            if (kdcKey == null)
            {
                throw new ArgumentNullException(nameof(kdcKey));
            }

            var cammac = new KrbAdCammac
            {
                Elements = elements
            };

            // Encode the elements for MAC computation
            var encodedElements = EncodeElements(elements);

            // KDC verifier using the KDC key
            cammac.KdcVerifier = CreateVerifier(encodedElements, kdcKey);

            // Optional service verifier
            if (serviceKey != null)
            {
                cammac.ServiceVerifier = CreateVerifier(encodedElements, serviceKey);
            }

            return cammac;
        }

        /// <summary>
        /// Validate the KDC verifier MAC.
        /// </summary>
        /// <param name="kdcKey">The KDC key to validate against.</param>
        /// <returns>True if the KDC verifier is valid; otherwise false.</returns>
        public bool ValidateKdcVerifier(KerberosKey kdcKey)
        {
            if (this.KdcVerifier?.Mac == null)
            {
                return false;
            }

            return ValidateVerifier(this.Elements, this.KdcVerifier, kdcKey);
        }

        /// <summary>
        /// Validate the service verifier MAC.
        /// </summary>
        /// <param name="serviceKey">The service key to validate against.</param>
        /// <returns>True if the service verifier is valid; otherwise false.</returns>
        public bool ValidateServiceVerifier(KerberosKey serviceKey)
        {
            if (this.ServiceVerifier?.Mac == null)
            {
                return false;
            }

            return ValidateVerifier(this.Elements, this.ServiceVerifier, serviceKey);
        }

        /// <summary>
        /// Wrap this CAMMAC as a <see cref="KrbAuthorizationData"/> element with type <see cref="AuthorizationDataType.AdCammac"/>.
        /// </summary>
        public KrbAuthorizationData ToAuthorizationData()
        {
            return new KrbAuthorizationData
            {
                Type = AuthorizationDataType.AdCammac,
                Data = this.Encode()
            };
        }

        private static KrbVerifierMac CreateVerifier(ReadOnlyMemory<byte> encodedElements, KerberosKey key)
        {
            var checksum = KrbChecksum.Create(encodedElements, key, KeyUsage.CammacChecksum);

            return new KrbVerifierMac
            {
                Mac = checksum,
                EncryptionType = key.EncryptionType
            };
        }

        private static bool ValidateVerifier(KrbAuthorizationData[] elements, KrbVerifierMac verifier, KerberosKey key)
        {
            try
            {
                var encodedElements = EncodeElements(elements);

                var validator = CryptoService.CreateChecksum(
                    verifier.Mac.Type,
                    signature: verifier.Mac.Checksum,
                    signatureData: encodedElements
                );

                if (validator == null)
                {
                    return false;
                }

                validator.Usage = KeyUsage.CammacChecksum;
                validator.Validate(key);

                return true;
            }
            catch
            {
                return false;
            }
        }

        private static ReadOnlyMemory<byte> EncodeElements(KrbAuthorizationData[] elements)
        {
            var sequence = new KrbAuthorizationDataSequence
            {
                AuthorizationData = elements
            };

            return sequence.Encode();
        }
    }
}
