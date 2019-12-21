using Kerberos.NET.Asn1;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using System;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Asn1;
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
            PrivateKey = cert.PrivateKey;
            PublicKey = cert.PublicKey;

            UserName = username;

            if (!string.IsNullOrWhiteSpace(domain))
            {
                Domain = domain.ToUpperInvariant();
            }

            agreement = StartKeyAgreement();
        }

        public X509Certificate2 Certificate { get; }

        public AsymmetricAlgorithm PrivateKey { get; }

        public PublicKey PublicKey { get; }

        private static readonly Oid IdPkInitAuthData = new Oid("1.3.6.1.5.2.3.1");
        private static readonly Oid DiffieHellman = new Oid("1.2.840.10046.2.1");

        private readonly IKeyAgreement agreement;

        protected virtual IKeyAgreement StartKeyAgreement()
        {
            return CryptoPal.Platform.DiffieHellmanModp14();
        }

        protected virtual bool CacheKeyAgreementParameters(IKeyAgreement agreement) => false;

        private ReadOnlyMemory<byte> clientDHNonce;

        private static ReadOnlyMemory<byte> DepadRight(ReadOnlyMemory<byte> data)
        {
            var result = data;

            for (var i = data.Length - 1; i > 0; i--)
            {
                if (data.Span[i] == 0)
                {
                    result = result.Slice(0, i);
                }
                else
                {
                    break;
                }
            }

            return result;
        }

        private static ReadOnlyMemory<byte> DepadLeft(ReadOnlyMemory<byte> data)
        {
            var result = data;

            for (var i = 0; i < data.Length; i++)
            {
                if (data.Span[i] == 0)
                {
                    result = result.Slice(i + 1);
                }
                else
                {
                    break;
                }
            }

            return result;
        }

        private static ReadOnlyMemory<byte> Pad(ReadOnlyMemory<byte> pv)
        {
            if (pv.Span[0] != 0)
            {
                var copy = new Memory<byte>(new byte[pv.Length + 1]);

                pv.CopyTo(copy.Slice(1));

                pv = copy;
            }

            return pv;
        }

        public override void TransformKdcReq(KrbKdcReq req)
        {
            var padata = req.PaData.ToList();

            var sha1 = CryptoPal.Platform.Sha1();

            var paChecksum = sha1.ComputeHash(req.Body.Encode().Span);

            var parametersAreCached = CacheKeyAgreementParameters(agreement);

            if (parametersAreCached)
            {
                clientDHNonce = GenerateNonce(req.Body.EType.FirstOrDefault(), agreement.PublicKey.KeyLength);
            }

            var domainParams = new KrbDiffieHellmanDomainParameters
            {
                P = Pad(agreement.PublicKey.Modulus),
                G = DepadRight(agreement.PublicKey.Generator),
                Q = agreement.PublicKey.Factor
            };

            var authPack = new KrbAuthPack
            {
                PKAuthenticator = new KrbPKAuthenticator
                {
                    Nonce = req.Body.Nonce,
                    PaChecksum = paChecksum
                },
                ClientPublicValue = new KrbSubjectPublicKeyInfo
                {
                    Algorithm = new KrbAlgorithmIdentifier
                    {
                        Algorithm = DiffieHellman,
                        Parameters = domainParams.EncodeSpecial()
                    },
                    SubjectPublicKey = EncodePublicKey(agreement.PublicKey)
                },
                ClientDHNonce = clientDHNonce
            };

            KerberosConstants.Now(out authPack.PKAuthenticator.CTime, out authPack.PKAuthenticator.CuSec);

            SignedCms signed = new SignedCms(
                new ContentInfo(
                    IdPkInitAuthData,
                    authPack.Encode().ToArray()
                )
            );

            signed.ComputeSignature(new CmsSigner(Certificate));

            var encoded = signed.Encode();

            var pk = new KrbPaPkAsReq
            {
                SignedAuthPack = encoded
            };

            padata.Add(new KrbPaData
            {
                Type = PaDataType.PA_PK_AS_REQ,
                Value = pk.Encode()
            });

            req.PaData = padata.ToArray();
        }

        private ReadOnlyMemory<byte> GenerateNonce(EncryptionType encryptionType, int minSize)
        {
            var transformer = CryptoService.CreateTransform(encryptionType);

            return transformer.GenerateRandomBytes(minSize);
        }

        public override T DecryptKdcRep<T>(KrbKdcRep kdcRep, KeyUsage keyUsage, Func<ReadOnlyMemory<byte>, T> func)
        {
            var paPkRep = kdcRep.PaData.FirstOrDefault(a => a.Type == PaDataType.PA_PK_AS_REP);

            if (paPkRep == null)
            {
                throw new KerberosProtocolException("PA-Data doesn't constain PA-PK-AS-REP");
            }

            var pkRep = KrbPaPkAsRep.Decode(paPkRep.Value);

            var dhKeyInfo = ValidateDHReply(pkRep);

            var kdcPublicKey = ParsePublicKey(dhKeyInfo.SubjectPublicKey);

            agreement.ImportPartnerKey(new DiffieHellmanKey
            {
                Public = DepadLeft(kdcPublicKey)
            });

            var derivedKey = agreement.GenerateAgreement();

            ReadOnlySpan<byte> serverDHNonce = default;

            if (pkRep.DHInfo.ServerDHNonce.HasValue)
            {
                serverDHNonce = pkRep.DHInfo.ServerDHNonce.Value.Span;
            }

            var transform = CryptoService.CreateTransform(kdcRep.EncPart.EType);

            sharedSecret = PKInitString2Key.String2Key(derivedKey.Span, transform.KeySize, clientDHNonce.Span, serverDHNonce);

            return base.DecryptKdcRep(kdcRep, keyUsage, func);
        }

        private ReadOnlyMemory<byte> sharedSecret;

        private static ReadOnlyMemory<byte> ParsePublicKey(ReadOnlyMemory<byte> data)
        {
            var reader = new AsnReader(data, AsnEncodingRules.DER);

            var bytes = reader.ReadIntegerBytes().ToArray();

            return bytes;
        }

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

        private static ReadOnlyMemory<byte> EncodePublicKey(DiffieHellmanKey publicKey)
        {
            using (var writer = new AsnWriter(AsnEncodingRules.DER))
            {
                writer.WriteKeyParameterInteger(publicKey.Public.Span);

                return writer.EncodeAsMemory();
            }
        }

        private static string TryExtractPrincipalName(X509Certificate2 cert)
        {
            return cert.Subject;
        }

        public override void Validate()
        {
            base.Validate();

            if (PrivateKey == null)
            {
                throw new ArgumentException("A Private Key must be set", nameof(PrivateKey));
            }

            if (PublicKey == null)
            {
                throw new ArgumentException("A Public Key must be set", nameof(PublicKey));
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
