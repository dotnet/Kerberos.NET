using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace Kerberos.NET.Server
{
    public class PaDataPkAsReqHandler : KdcPreAuthenticationHandlerBase
    {
        private static readonly Oid IdPkInitDHKeyData = new Oid("1.3.6.1.5.2.3.2");
        private static readonly Oid DiffieHellman = new Oid("1.2.840.10046.2.1");
        private static readonly Oid EllipticCurveDiffieHellman = new Oid("1.2.840.10045.2.1");

        public X509IncludeOption IncludeOption { get; set; } = X509IncludeOption.ExcludeRoot;

        public PaDataPkAsReqHandler(IRealmService service)
            : base(service)
        {
        }

        public override async Task<KrbPaData> Validate(KrbKdcReq asReq, PreAuthenticationContext preauth)
        {
            var paPk = asReq.PaData.FirstOrDefault(p => p.Type == PaDataType.PA_PK_AS_REQ);

            if (paPk == null)
            {
                return null;
            }

            var pkreq = KrbPaPkAsReq.Decode(paPk.Value);

            var authPack = await ValidateAuthPack(preauth.Principal, pkreq);

            ValidateAuthenticator(authPack.PKAuthenticator, asReq.Body);

            var requestAlg = authPack.ClientPublicValue?.Algorithm?.Algorithm;

            IKeyAgreement agreement;

            if (requestAlg?.Value == EllipticCurveDiffieHellman.Value)
            {
                agreement = FromEllipticCurveDomainParameters(authPack.ClientPublicValue);
            }
            else if (requestAlg?.Value == DiffieHellman.Value)
            {
                agreement = await FromDiffieHellmanDomainParametersAsync(authPack.ClientPublicValue);
            }
            else
            {
                throw OnlyKeyAgreementSupportedException();
            }

            var derivedKey = agreement.GenerateAgreement();

            var etype = asReq.Body.EType.First();

            var transform = CryptoService.CreateTransform(etype);

            ReadOnlyMemory<byte> clientDHNonce = authPack.ClientDHNonce.GetValueOrDefault();
            ReadOnlyMemory<byte> serverDHNonce = default;

            if (clientDHNonce.Length > 0)
            {
                serverDHNonce = transform.GenerateRandomBytes(agreement.PublicKey.KeyLength);

                await Service.Principals.CacheKey(agreement.PrivateKey);
            }

            var keyInfo = new KrbKdcDHKeyInfo { SubjectPublicKey = agreement.PublicKey.EncodePublicKey() };

            if (agreement.PublicKey.CacheExpiry.HasValue)
            {
                keyInfo.DHKeyExpiration = agreement.PublicKey.CacheExpiry;
                keyInfo.Nonce = authPack.PKAuthenticator.Nonce;
            }

            var sessionKey = PKInitString2Key.String2Key(
                derivedKey.Span,
                transform.KeySize,
                clientDHNonce.Span,
                serverDHNonce.Span
            );

            var paPkRep = new KrbPaPkAsRep
            {
                DHInfo = new KrbDHReplyInfo
                {
                    DHSignedData = await SignDHResponseAsync(keyInfo),
                    ServerDHNonce = serverDHNonce
                }
            };

            preauth.PaData = new[]
            {
                new KrbPaData
                {
                    Type = PaDataType.PA_PK_AS_REP,
                    Value = paPkRep.Encode()
                }
            };

            preauth.EncryptedPartKey = new KerberosKey(key: sessionKey.ToArray(), etype: etype);

            return null;
        }

        private async Task<ReadOnlyMemory<byte>> SignDHResponseAsync(KrbKdcDHKeyInfo keyInfo)
        {
            var signed = new SignedCms(
                new ContentInfo(
                    IdPkInitDHKeyData,
                    keyInfo.Encode().ToArray()
                )
            );

            var certificate = await Service.Principals.RetrieveKdcCertificate();

            var signer = new CmsSigner(certificate) { IncludeOption = IncludeOption };

            signed.ComputeSignature(signer);

            return signed.Encode();
        }

        private static Exception OnlyKeyAgreementSupportedException() => throw new NotSupportedException("Only key agreement is supported for PKINIT authentication");

        private async Task<IKeyAgreement> FromDiffieHellmanDomainParametersAsync(KrbSubjectPublicKeyInfo clientPublicValue)
        {
            var parameters = KrbDiffieHellmanDomainParameters.DecodeSpecial(clientPublicValue.Algorithm.Parameters.Value);

            IKeyAgreement agreement = null;

            switch (parameters.P.Length)
            {
                case 128:
                    agreement = CryptoPal.Platform.DiffieHellmanModp2(
                        await Service.Principals.RetrieveKeyCache(KeyAgreementAlgorithm.DiffieHellmanModp2)
                    );
                    break;
                case 256:
                    agreement = CryptoPal.Platform.DiffieHellmanModp14(
                      await Service.Principals.RetrieveKeyCache(KeyAgreementAlgorithm.DiffieHellmanModp14)
                    );
                    break;
                default:
                    throw new InvalidOperationException("Unknown key agreement parameter");
            }

            var publicKey = DiffieHellmanKey.ParsePublicKey(clientPublicValue.SubjectPublicKey, agreement.PublicKey.KeyLength);

            agreement.ImportPartnerKey(publicKey);

            return agreement;
        }

        private IKeyAgreement FromEllipticCurveDomainParameters(KrbSubjectPublicKeyInfo _)
        {
            throw new NotImplementedException();
        }

        private void ValidateAuthenticator(KrbPKAuthenticator authenticator, KrbKdcReqBody body)
        {
            using (var sha1 = CryptoPal.Platform.Sha1())
            {
                var encoded = body.Encode();

                var paChecksum = sha1.ComputeHash(encoded.Span);

                if (!KerberosCryptoTransformer.AreEqualSlow(paChecksum.Span, authenticator.PaChecksum.Value.Span))
                {
                    throw new SecurityException("Invalid checksum");
                }
            }

            if (!KerberosConstants.WithinSkew(Service.Now(), authenticator.CTime, authenticator.CuSec, Service.Settings.MaximumSkew))
            {
                throw new KerberosValidationException($"PKAuthenticator time skew too great");
            }

            ValidateNonce(authenticator.Nonce);
        }

        protected virtual void ValidateNonce(int nonce)
        {
            Debug.Assert(nonce > 0);
        }

        private static async Task<KrbAuthPack> ValidateAuthPack(IKerberosPrincipal principal, KrbPaPkAsReq pkreq)
        {
            SignedCms signedCms = new SignedCms();
            signedCms.Decode(pkreq.SignedAuthPack.ToArray());

            signedCms.CheckSignature(verifySignatureOnly: true);

            await principal.Validate(signedCms.Certificates);

            var authPack = KrbAuthPack.Decode(signedCms.ContentInfo.Content);

            return authPack;
        }

        public override Task PostValidate(IKerberosPrincipal principal, List<KrbPaData> preAuthRequirements)
        {
            return base.PostValidate(principal, preAuthRequirements);
        }
    }
}
