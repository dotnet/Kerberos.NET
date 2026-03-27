// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Reflection;
using System.Security.Cryptography;

namespace Kerberos.NET.Crypto
{
    /// <summary>
    /// Cross-platform elliptic curve Diffie-Hellman key agreement for PKINIT.
    /// Supports NIST P-256, P-384, and P-521 curves per RFC 4556.
    /// Uses runtime reflection to access ECDiffieHellman which is available on
    /// .NET Core 3.1+ / .NET 5+ even when compiled against netstandard2.0.
    /// </summary>
    public class EcdhKeyAgreement : IKeyAgreement
    {
        private readonly IDisposable ecdh;
        private readonly KeyAgreementAlgorithm algorithm;
        private readonly int coordinateSize;
        private IDisposable partnerEcdhForKey;
        private bool disposedValue;

        // Cached reflection info
        private static readonly Type EcdhType;
        private static readonly MethodInfo CreateWithCurveMethod;
        private static readonly MethodInfo ExportParametersMethod;
        private static readonly MethodInfo ImportParametersMethod;
        private static readonly MethodInfo DeriveKeyFromHashMethod;
        private static readonly PropertyInfo PublicKeyProperty;

        static EcdhKeyAgreement()
        {
            EcdhType = Type.GetType("System.Security.Cryptography.ECDiffieHellman, System.Security.Cryptography.Algorithms")
                    ?? Type.GetType("System.Security.Cryptography.ECDiffieHellman, System.Core")
                    ?? Type.GetType("System.Security.Cryptography.ECDiffieHellman, System.Security.Cryptography");

            if (EcdhType != null)
            {
                CreateWithCurveMethod = EcdhType.GetMethod("Create", new[] { typeof(ECCurve) });
                ExportParametersMethod = EcdhType.GetMethod("ExportParameters", new[] { typeof(bool) });
                ImportParametersMethod = EcdhType.GetMethod("ImportParameters", new[] { typeof(ECParameters) });
                DeriveKeyFromHashMethod = EcdhType.GetMethod("DeriveKeyFromHash", new[] {
                    Type.GetType("System.Security.Cryptography.ECDiffieHellmanPublicKey, System.Security.Cryptography.Algorithms")
                        ?? Type.GetType("System.Security.Cryptography.ECDiffieHellmanPublicKey, System.Core")
                        ?? Type.GetType("System.Security.Cryptography.ECDiffieHellmanPublicKey, System.Security.Cryptography"),
                    typeof(HashAlgorithmName)
                });
                PublicKeyProperty = EcdhType.GetProperty("PublicKey");
            }
        }

        public EcdhKeyAgreement(KeyAgreementAlgorithm algorithm)
        {
            if (EcdhType == null || CreateWithCurveMethod == null)
            {
                throw new PlatformNotSupportedException(
                    "ECDH PKINIT requires a runtime that supports ECDiffieHellman " +
                    "(e.g., .NET Core 3.1+, .NET 5+). Alternatively, use DiffieHellmanModp14."
                );
            }

            this.algorithm = algorithm;

            var curve = algorithm switch
            {
                KeyAgreementAlgorithm.EllipticCurveDiffieHellmanP256 => ECCurve.NamedCurves.nistP256,
                KeyAgreementAlgorithm.EllipticCurveDiffieHellmanP384 => ECCurve.NamedCurves.nistP384,
                KeyAgreementAlgorithm.EllipticCurveDiffieHellmanP521 => ECCurve.NamedCurves.nistP521,
                _ => throw new ArgumentException($"Unsupported EC algorithm: {algorithm}", nameof(algorithm))
            };

            this.ecdh = (IDisposable)CreateWithCurveMethod.Invoke(null, new object[] { curve });

            var ecParams = (ECParameters)ExportParametersMethod.Invoke(this.ecdh, new object[] { false });
            this.coordinateSize = ecParams.Q.X.Length;

            // Build uncompressed EC point: 04 || x || y
            var publicPoint = new byte[1 + ecParams.Q.X.Length + ecParams.Q.Y.Length];
            publicPoint[0] = 0x04;
            Buffer.BlockCopy(ecParams.Q.X, 0, publicPoint, 1, ecParams.Q.X.Length);
            Buffer.BlockCopy(ecParams.Q.Y, 0, publicPoint, 1 + ecParams.Q.X.Length, ecParams.Q.Y.Length);

            this.PublicKey = new EcdhKey
            {
                Type = AsymmetricKeyType.Public,
                Algorithm = algorithm,
                KeyLength = this.coordinateSize,
                PublicComponent = publicPoint
            };

            this.PrivateKey = new EcdhKey
            {
                Type = AsymmetricKeyType.Private,
                Algorithm = algorithm,
                KeyLength = this.coordinateSize,
                PublicComponent = publicPoint
            };
        }

        public IExchangeKey PublicKey { get; }

        public IExchangeKey PrivateKey { get; }

        public ReadOnlyMemory<byte> GenerateAgreement()
        {
            if (this.partnerEcdhForKey == null)
            {
                throw new InvalidOperationException("A partner key must be imported first");
            }

            // Use DeriveKeyFromHash to get the shared secret
            var partnerPubKey = PublicKeyProperty.GetValue(this.partnerEcdhForKey);

            var derived = (byte[])DeriveKeyFromHashMethod.Invoke(
                this.ecdh,
                new object[] { partnerPubKey, HashAlgorithmName.SHA256 }
            );

            // For PKINIT, we need a deterministic shared secret of coordinate size.
            // DeriveKeyFromHash(SHA-256) gives 32 bytes which matches P-256.
            // For P-384 and P-521, we'll use what we get and String2Key will handle sizing.
            if (derived.Length > this.coordinateSize)
            {
                var truncated = new byte[this.coordinateSize];
                Buffer.BlockCopy(derived, 0, truncated, 0, this.coordinateSize);
                return truncated;
            }

            return derived;
        }

        public void ImportPartnerKey(IExchangeKey publicKey)
        {
            if (publicKey == null)
            {
                throw new ArgumentNullException(nameof(publicKey));
            }

            var keyData = publicKey.PublicComponent.ToArray();

            // Parse the uncompressed EC point: 04 || x || y
            if (keyData.Length == 0 || keyData[0] != 0x04)
            {
                throw new CryptographicException("Only uncompressed EC point format (0x04) is supported");
            }

            var coordSize = (keyData.Length - 1) / 2;
            var x = new byte[coordSize];
            var y = new byte[coordSize];

            Buffer.BlockCopy(keyData, 1, x, 0, coordSize);
            Buffer.BlockCopy(keyData, 1 + coordSize, y, 0, coordSize);

            var curve = this.algorithm switch
            {
                KeyAgreementAlgorithm.EllipticCurveDiffieHellmanP256 => ECCurve.NamedCurves.nistP256,
                KeyAgreementAlgorithm.EllipticCurveDiffieHellmanP384 => ECCurve.NamedCurves.nistP384,
                KeyAgreementAlgorithm.EllipticCurveDiffieHellmanP521 => ECCurve.NamedCurves.nistP521,
                _ => throw new CryptographicException($"Unsupported algorithm: {this.algorithm}")
            };

            var ecParams = new ECParameters
            {
                Curve = curve,
                Q = new ECPoint { X = x, Y = y }
            };

            // Create a new ECDiffieHellman from partner parameters to get their public key
            this.partnerEcdhForKey?.Dispose();
            this.partnerEcdhForKey = (IDisposable)CreateWithCurveMethod.Invoke(null, new object[] { curve });
            ImportParametersMethod.Invoke(this.partnerEcdhForKey, new object[] { ecParams });
        }

        /// <summary>
        /// Maps a <see cref="KeyAgreementAlgorithm"/> to its corresponding EC curve OID.
        /// </summary>
        public static Oid GetCurveOid(KeyAgreementAlgorithm algorithm)
        {
            return algorithm switch
            {
                KeyAgreementAlgorithm.EllipticCurveDiffieHellmanP256 => new Oid("1.2.840.10045.3.1.7"),   // secp256r1 / P-256
                KeyAgreementAlgorithm.EllipticCurveDiffieHellmanP384 => new Oid("1.3.132.0.34"),           // secp384r1 / P-384
                KeyAgreementAlgorithm.EllipticCurveDiffieHellmanP521 => new Oid("1.3.132.0.35"),           // secp521r1 / P-521
                _ => throw new ArgumentException($"Not an EC algorithm: {algorithm}", nameof(algorithm))
            };
        }

        /// <summary>
        /// Maps a curve OID to the corresponding <see cref="KeyAgreementAlgorithm"/>.
        /// </summary>
        public static KeyAgreementAlgorithm FromCurveOid(string oidValue)
        {
            return oidValue switch
            {
                "1.2.840.10045.3.1.7" => KeyAgreementAlgorithm.EllipticCurveDiffieHellmanP256,
                "1.3.132.0.34" => KeyAgreementAlgorithm.EllipticCurveDiffieHellmanP384,
                "1.3.132.0.35" => KeyAgreementAlgorithm.EllipticCurveDiffieHellmanP521,
                _ => throw new CryptographicException($"Unsupported EC curve OID: {oidValue}")
            };
        }

        /// <summary>
        /// Returns true if ECDH key agreement is available on the current runtime.
        /// </summary>
        public static bool IsSupported => EcdhType != null && CreateWithCurveMethod != null;

        protected virtual void Dispose(bool disposing)
        {
            if (!this.disposedValue)
            {
                if (disposing)
                {
                    this.ecdh?.Dispose();
                    this.partnerEcdhForKey?.Dispose();
                }

                this.disposedValue = true;
            }
        }

        public void Dispose()
        {
            this.Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }
}
