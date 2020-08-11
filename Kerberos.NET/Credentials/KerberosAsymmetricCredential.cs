using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace Kerberos.NET.Credentials
{
    /// <summary>
    /// A credential used for PKINIT during client authentication. This relies on client certificates
    /// to authenticate callers to the KDC. The KDC will follow defined processes to validate the certificate.
    /// </summary>
    public class KerberosAsymmetricCredential : KerberosCredential, IDisposable
    {
        private static readonly Oid IdPkInitAuthData = new Oid("1.3.6.1.5.2.3.1");
        private static readonly Oid DiffieHellman = new Oid("1.2.840.10046.2.1");

        private ReadOnlyMemory<byte> clientDHNonce;
        private IKeyAgreement agreement;

        /// <summary>
        /// Creates a new instance of an asymmetric credential.
        /// </summary>
        /// <param name="cert">The certificate used to authenticate the client.</param>
        /// <param name="username">Optionally an NT_PRINCIPAL name can be supplied as a 
        /// hint otherwise the username will be pulled from the certificate.</param>
        public KerberosAsymmetricCredential(
            X509Certificate2 cert,
            string username = null
        )
        {
            if (cert == null)
            {
                throw new ArgumentException("Certificate cannot be null", nameof(cert));
            }

            if (!cert.HasPrivateKey)
            {
                throw new ArgumentException("Certificate must have a private key", nameof(cert.PrivateKey));
            }

            if (string.IsNullOrWhiteSpace(username))
            {
                username = TryExtractPrincipalName(cert);
            }

            string domain = null;

            TrySplitUserNameDomain(username, out username, ref domain);

            Certificate = cert;

            UserName = username;

            if (!string.IsNullOrWhiteSpace(domain))
            {
                Domain = domain.ToUpperInvariant();
            }
        }

        /// <summary>
        /// The certificate used during client authentication.
        /// </summary>
        public X509Certificate2 Certificate { get; }

        /// <summary>
        /// Indicates whether the credential has enough information to skip the initial KDC prompt for credentials step.
        /// </summary>
        public override bool SupportsOptimisticPreAuthentication => Certificate != null;

        /// <summary>
        /// Indicates how the client certificate should be packaged into the request to the KDC.
        /// </summary>
        public X509IncludeOption IncludeOption { get; set; } = X509IncludeOption.ExcludeRoot;

        /// <summary>
        /// Indicates what key agreement algorithm should be used to negotiate session keys.
        /// </summary>
        public KeyAgreementAlgorithm KeyAgreement { get; set; } = KeyAgreementAlgorithm.DiffieHellmanModp14;

        /// <summary>
        /// Indicates whether the credential should prefer Elliptive Curve algorithms.
        /// </summary>
        public bool SupportsEllipticCurveDiffieHellman { get; set; } = false;

        /// <summary>
        /// Indicates whether the credential should prefer the Diffie-Hellman algorithm.
        /// </summary>
        public bool SupportsDiffieHellman { get; set; } = true;

        /// <summary>
        /// Creates the <see cref="IKeyAgreement"/> that is used to derive session keys.
        /// </summary>
        /// <returns>Returns <see cref="IKeyAgreement"/> to derive session keys.</returns>
        protected virtual IKeyAgreement StartKeyAgreement()
        {
            // We should try and pick smart defaults based on what we know if it's set to none

            if (KeyAgreement == KeyAgreementAlgorithm.None)
            {
                if (SupportsEllipticCurveDiffieHellman)
                {
                    KeyAgreement = KeyAgreementAlgorithm.EllipticCurveDiffieHellmanP256;
                }
                else if (SupportsDiffieHellman)
                {
                    KeyAgreement = KeyAgreementAlgorithm.DiffieHellmanModp14;
                }
            }

            // if neither EC nor DH are enabled then KeyAgreement still equals None
            // None will fall through to null which is validated in TransformKdcReq

            switch (KeyAgreement)
            {
                case KeyAgreementAlgorithm.DiffieHellmanModp2 when SupportsDiffieHellman:
                    return CryptoPal.Platform.DiffieHellmanModp2();

                case KeyAgreementAlgorithm.DiffieHellmanModp14 when SupportsDiffieHellman:
                    return CryptoPal.Platform.DiffieHellmanModp14();

                case KeyAgreementAlgorithm.EllipticCurveDiffieHellmanP256 when SupportsEllipticCurveDiffieHellman:
                    return CryptoPal.Platform.DiffieHellmanP256();

                case KeyAgreementAlgorithm.EllipticCurveDiffieHellmanP384 when SupportsEllipticCurveDiffieHellman:
                    return CryptoPal.Platform.DiffieHellmanP384();

                case KeyAgreementAlgorithm.EllipticCurveDiffieHellmanP521 when SupportsEllipticCurveDiffieHellman:
                    return CryptoPal.Platform.DiffieHellmanP521();
            }

            return null;
        }

        /// <summary>
        /// If overridden this method will cache the key agreement private keys to reduce key generation time.
        /// Note that caching Key Agreement private keys is not recommended as these keys should be ephemeral.
        /// </summary>
        /// <param name="agreement">The agreement private key to cache.</param>
        /// <returns>Returns true if the key was cached, otherwise it will return false.</returns>
        protected virtual bool CacheKeyAgreementParameters(IKeyAgreement agreement) => false;

        /// <summary>
        /// Applies credential-specific changes to the KDC-REQ message and is what supplies the PKINIT properties to the request.
        /// </summary>
        /// <param name="req">The <see cref="KrbKdcReq"/> that will be modified.</param>
        public override void TransformKdcReq(KrbKdcReq req)
        {
            agreement = StartKeyAgreement();

            // We don't support the straight RSA mode because
            // it doesn't rely on ephemeral key agreement
            // which isn't great security-wise

            if (agreement == null)
            {
                throw OnlyKeyAgreementSupportedException();
            }

            var padata = req.PaData.ToList();

            KrbAuthPack authPack;

            if (SupportsEllipticCurveDiffieHellman)
            {
                authPack = CreateEllipticCurveDiffieHellmanAuthPack(req.Body);
            }
            else if (SupportsDiffieHellman)
            {
                authPack = CreateDiffieHellmanAuthPack(req.Body);
            }
            else
            {
                throw OnlyKeyAgreementSupportedException();
            }

            KerberosConstants.Now(out authPack.PKAuthenticator.CTime, out authPack.PKAuthenticator.CuSec);

            SignedCms signed = new SignedCms(
                new ContentInfo(
                    IdPkInitAuthData,
                    authPack.Encode().ToArray()
                )
            );

            var signer = new CmsSigner(Certificate) { IncludeOption = IncludeOption };

            signed.ComputeSignature(signer, silent: true);

            var pk = new KrbPaPkAsReq { SignedAuthPack = signed.Encode() };

            padata.Add(new KrbPaData
            {
                Type = PaDataType.PA_PK_AS_REQ,
                Value = pk.Encode()
            });

            req.PaData = padata.ToArray();
        }

        private static Exception OnlyKeyAgreementSupportedException() => throw new NotSupportedException("Only key agreement is supported for PKINIT authentication");

        private KrbAuthPack CreateEllipticCurveDiffieHellmanAuthPack(KrbKdcReqBody _)
        {
            throw new NotImplementedException();
        }

        private KrbAuthPack CreateDiffieHellmanAuthPack(KrbKdcReqBody body)
        {
            using (var sha1 = CryptoPal.Platform.Sha1())
            {
                var encoded = body.Encode();

                var paChecksum = sha1.ComputeHash(encoded);

                var parametersAreCached = CacheKeyAgreementParameters(agreement);

                if (parametersAreCached)
                {
                    clientDHNonce = GenerateNonce(body.EType.First(), agreement.PublicKey.KeyLength);
                }

                var domainParams = KrbDiffieHellmanDomainParameters.FromKeyAgreement(agreement);

                var authPack = new KrbAuthPack
                {
                    PKAuthenticator = new KrbPKAuthenticator
                    {
                        Nonce = body.Nonce,
                        PaChecksum = paChecksum
                    },
                    ClientPublicValue = new KrbSubjectPublicKeyInfo
                    {
                        Algorithm = new KrbAlgorithmIdentifier
                        {
                            Algorithm = DiffieHellman,
                            Parameters = domainParams.EncodeSpecial()
                        },
                        SubjectPublicKey = agreement.PublicKey.EncodePublicKey()
                    },
                    ClientDHNonce = clientDHNonce
                };

                return authPack;
            }
        }

        private static ReadOnlyMemory<byte> GenerateNonce(EncryptionType encryptionType, int minSize)
        {
            var transformer = CryptoService.CreateTransform(encryptionType);

            return transformer.GenerateRandomBytes(minSize);
        }

        /// <summary>
        /// Decrypts the response from the KDC using credential-supplied secrets.
        /// </summary>
        /// <typeparam name="T">The return type</typeparam>
        /// <param name="kdcRep">The response from the KDC to decrypt</param>
        /// <param name="keyUsage">The KeyUsage salt used to decrypt the response</param>
        /// <param name="func">The parsing function to process the decrypted response</param>
        /// <returns>Returns <typeparamref name="T"/> after decryption</returns>
        public override T DecryptKdcRep<T>(KrbKdcRep kdcRep, KeyUsage keyUsage, Func<ReadOnlyMemory<byte>, T> func)
        {
            var paPkRep = kdcRep?.PaData?.FirstOrDefault(a => a.Type == PaDataType.PA_PK_AS_REP);

            if (paPkRep == null)
            {
                throw new KerberosProtocolException("PA-Data doesn't contain PA-PK-AS-REP");
            }

            var pkRep = KrbPaPkAsRep.Decode(paPkRep.Value);

            if (pkRep.DHInfo != null)
            {
                sharedSecret = DeriveDHKeyAgreement(kdcRep, pkRep);
            }
            else
            {
                throw OnlyKeyAgreementSupportedException();
            }

            return base.DecryptKdcRep(kdcRep, keyUsage, func);
        }

        private ReadOnlyMemory<byte> DeriveDHKeyAgreement(KrbKdcRep kdcRep, KrbPaPkAsRep pkRep)
        {
            var dhKeyInfo = ValidateDHReply(pkRep);

            var kdcPublicKey = DiffieHellmanKey.ParsePublicKey(dhKeyInfo.SubjectPublicKey, agreement.PublicKey.KeyLength);

            agreement.ImportPartnerKey(kdcPublicKey);

            var derivedKey = agreement.GenerateAgreement();

            ReadOnlySpan<byte> serverDHNonce = default;

            if (pkRep.DHInfo.ServerDHNonce.HasValue)
            {
                serverDHNonce = pkRep.DHInfo.ServerDHNonce.Value.Span;
            }

            var transform = CryptoService.CreateTransform(kdcRep.EncPart.EType);

            return PKInitString2Key.String2Key(derivedKey.Span, transform.KeySize, clientDHNonce.Span, serverDHNonce);
        }

        private ReadOnlyMemory<byte> sharedSecret;

        private KrbKdcDHKeyInfo ValidateDHReply(KrbPaPkAsRep pkRep)
        {
            var signed = new SignedCms();

            signed.Decode(pkRep.DHInfo.DHSignedData.ToArray());

            VerifyKdcSignature(signed);

            return KrbKdcDHKeyInfo.Decode(signed.ContentInfo.Content);
        }

        /// <summary>
        /// Verifies the PKINIT response from the KDC is signed and validates as expected. 
        /// Throws <see cref="CryptographicException"/> if the KDC certificate cannot be validated.
        /// </summary>
        /// <param name="signed">The signed CMS message within the response</param>
        protected virtual void VerifyKdcSignature(SignedCms signed)
        {
            signed.CheckSignature(verifySignatureOnly: false);
        }

        private static string TryExtractPrincipalName(X509Certificate2 cert)
        {
            return cert.Subject;
        }

        /// <summary>
        /// Validates the credential is well-formed before attempting to use it.
        /// </summary>
        public override void Validate()
        {
            base.Validate();

            if (Certificate.PrivateKey == null)
            {
                throw new ArgumentException("A Private Key must be set", nameof(Certificate.PrivateKey));
            }

            if (Certificate.PublicKey == null)
            {
                throw new ArgumentException("A Public Key must be set", nameof(Certificate.PublicKey));
            }
        }

        /// <summary>
        /// Creates the session key used by the KDC exchange.
        /// </summary>
        /// <returns>Returns the Key Agreement shared secret</returns>
        public override KerberosKey CreateKey()
        {
            return new KerberosKey(key: sharedSecret.ToArray());
        }

        public void Dispose()
        {
            if (agreement != null)
            {
                agreement.Dispose();
            }
        }
    }
}
