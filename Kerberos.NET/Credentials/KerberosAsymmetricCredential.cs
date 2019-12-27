using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace Kerberos.NET.Credentials
{
    public class KerberosAsymmetricCredential : KerberosCredential, IDisposable
    {
        public KerberosAsymmetricCredential(X509Certificate2 cert, string username = null)
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

            SupportsEllipticCurveDiffieHellman = false;
            SupportsDiffieHellman = true;

            agreement = StartKeyAgreement();
        }

        public X509Certificate2 Certificate { get; }

        private static readonly Oid IdPkInitAuthData = new Oid("1.3.6.1.5.2.3.1");
        private static readonly Oid DiffieHellman = new Oid("1.2.840.10046.2.1");

        private readonly IKeyAgreement agreement;

        protected virtual IKeyAgreement StartKeyAgreement()
        {
            if (SupportsEllipticCurveDiffieHellman)
            {
                return CryptoPal.Platform.DiffieHellmanP256();
            }

            if (SupportsDiffieHellman)
            {
                return CryptoPal.Platform.DiffieHellmanModp14();
            }

            return null;
        }

        public bool SupportsEllipticCurveDiffieHellman { get; }

        public bool SupportsDiffieHellman { get; }

        protected virtual bool CacheKeyAgreementParameters(IKeyAgreement agreement) => false;

        private ReadOnlyMemory<byte> clientDHNonce;

        public override void TransformKdcReq(KrbKdcReq req)
        {
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

            signed.ComputeSignature(new CmsSigner(Certificate));

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

                var paChecksum = sha1.ComputeHash(encoded.Span);

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

            var kdcPublicKey = DiffieHellmanKey.ParsePublicKey(dhKeyInfo.SubjectPublicKey);

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

        protected virtual void VerifyKdcSignature(SignedCms signed)
        {
            signed.CheckSignature(verifySignatureOnly: false);
        }

        private static string TryExtractPrincipalName(X509Certificate2 cert)
        {
            return cert.Subject;
        }

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
