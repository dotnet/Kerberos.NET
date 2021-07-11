// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using static Kerberos.NET.Entities.KerberosConstants;

namespace Kerberos.NET.Server
{
    public class PaDataPkAsReqHandler : KdcPreAuthenticationHandlerBase
    {
        private static readonly Oid IdPkInitDHKeyData = new Oid("1.3.6.1.5.2.3.2");
        private static readonly Oid DiffieHellman = new Oid("1.2.840.10046.2.1");
        private static readonly Oid EllipticCurveDiffieHellman = new Oid("1.2.840.10045.2.1");

        private static readonly ReadOnlyMemory<KeyAgreementAlgorithm> DefaultSupportedAlgorithms
            = new ReadOnlyMemory<KeyAgreementAlgorithm>(new[]
        {
            KeyAgreementAlgorithm.DiffieHellmanModp14,
            KeyAgreementAlgorithm.EllipticCurveDiffieHellmanP256,
            KeyAgreementAlgorithm.EllipticCurveDiffieHellmanP384,
            KeyAgreementAlgorithm.EllipticCurveDiffieHellmanP521
        });

        public X509IncludeOption IncludeOption { get; set; } = X509IncludeOption.ExcludeRoot;

        public ICollection<KeyAgreementAlgorithm> SupportedKeyAgreementAlgorithms { get; }
            = new List<KeyAgreementAlgorithm>(DefaultSupportedAlgorithms.ToArray());

        public PaDataPkAsReqHandler(IRealmService service)
            : base(service)
        {
        }

        public override void PreValidate(PreAuthenticationContext preauth)
        {
            if (preauth == null)
            {
                throw new ArgumentNullException(nameof(preauth));
            }

            var asReq = (KrbKdcReq)preauth.Message;

            var paPk = asReq.PaData.FirstOrDefault(p => p.Type == PaDataType.PA_PK_AS_REQ);

            if (paPk == null)
            {
                return;
            }

            var pkreq = KrbPaPkAsReq.Decode(paPk.Value);

            var signedCms = new SignedCms();
            signedCms.Decode(pkreq.SignedAuthPack.ToArray());

            var state = new PkInitState
            {
                PkInitRequest = pkreq,
                Cms = signedCms
            };

            state.ClientCertificate.AddRange(signedCms.Certificates);

            preauth.PreAuthenticationState[PaDataType.PA_PK_AS_REQ] = state;
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

            if (!preauth.PreAuthenticationState.TryGetValue(PaDataType.PA_PK_AS_REQ, out PaDataState paState) ||
                !(paState is PkInitState state))
            {
                return null;
            }

            var authPack = ValidateAuthPack(preauth, state);

            this.ValidateAuthenticator(authPack.PKAuthenticator, asReq.Body);

            var requestAlg = authPack.ClientPublicValue?.Algorithm?.Algorithm;

            IKeyAgreement agreement;

            if (requestAlg?.Value == EllipticCurveDiffieHellman.Value)
            {
                agreement = this.FromEllipticCurveDomainParameters(authPack.ClientPublicValue);
            }
            else if (requestAlg?.Value == DiffieHellman.Value)
            {
                agreement = this.FromDiffieHellmanDomainParameters(authPack.ClientPublicValue);
            }
            else
            {
                throw OnlyKeyAgreementSupportedException();
            }

            var derivedKey = agreement.GenerateAgreement();

            var preferredEType = GetPreferredEType(
                asReq.Body.EType,
                this.Service.Configuration.Defaults.PermittedEncryptionTypes,
                this.Service.Configuration.Defaults.AllowWeakCrypto
            );

            if (preferredEType is null)
            {
                throw new InvalidOperationException("Cannot find a common EType");
            }

            var etype = preferredEType.Value;

            var transform = CryptoService.CreateTransform(etype);

            ReadOnlyMemory<byte> clientDHNonce = authPack.ClientDHNonce.GetValueOrDefault();
            ReadOnlyMemory<byte> serverDHNonce = default;

            if (clientDHNonce.Length > 0)
            {
                serverDHNonce = transform.GenerateRandomBytes(agreement.PublicKey.KeyLength);

                this.Service.Principals.CacheKey(agreement.PrivateKey);
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
                    DHSignedData = this.SignDHResponse(keyInfo),
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
            preauth.ClientAuthority = PaDataType.PA_PK_AS_REQ;

            return null;
        }

        private ReadOnlyMemory<byte> SignDHResponse(KrbKdcDHKeyInfo keyInfo)
        {
            var signed = new SignedCms(
                new ContentInfo(
                    IdPkInitDHKeyData,
                    keyInfo.Encode().ToArray()
                )
            );

            var certificate = this.Service.Principals.RetrieveKdcCertificate();

            var signer = new CmsSigner(certificate) { IncludeOption = this.IncludeOption };

            signed.ComputeSignature(signer);

            return signed.Encode();
        }

        private static Exception OnlyKeyAgreementSupportedException() => throw new NotSupportedException("Only key agreement is supported for PKINIT authentication");

        private IKeyAgreement FromDiffieHellmanDomainParameters(KrbSubjectPublicKeyInfo clientPublicValue)
        {
            var parameters = KrbDiffieHellmanDomainParameters.DecodeSpecial(clientPublicValue.Algorithm.Parameters.Value);

            IKeyAgreement agreement;

            if (this.IsSupportedAlgorithm(KeyAgreementAlgorithm.DiffieHellmanModp14, Oakley.Group14.Prime, parameters.P))
            {
                var cachedKey = this.Service.Principals.RetrieveKeyCache(KeyAgreementAlgorithm.DiffieHellmanModp14);

                agreement = CryptoPal.Platform.DiffieHellmanModp14(cachedKey);
            }
            else if (this.IsSupportedAlgorithm(KeyAgreementAlgorithm.DiffieHellmanModp2, Oakley.Group2.Prime, parameters.P))
            {
                var cachedKey = this.Service.Principals.RetrieveKeyCache(KeyAgreementAlgorithm.DiffieHellmanModp2);

                agreement = CryptoPal.Platform.DiffieHellmanModp2(cachedKey);
            }
            else
            {
                var length = parameters.P.Length * 8;

                throw new InvalidOperationException($"Unsupported Diffie Hellman key agreement parameter with length {length}");
            }

            var publicKey = DiffieHellmanKey.ParsePublicKey(clientPublicValue.SubjectPublicKey, agreement.PublicKey.KeyLength);

            agreement.ImportPartnerKey(publicKey);

            return agreement;
        }

        private bool IsSupportedAlgorithm(KeyAgreementAlgorithm algorithm, ReadOnlyMemory<byte> expectedPVal, ReadOnlyMemory<byte> actualPVal)
        {
            if (!this.SupportedKeyAgreementAlgorithms.Contains(algorithm))
            {
                return false;
            }

            return expectedPVal.Span.SequenceEqual(actualPVal.Span);
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

            if (!WithinSkew(this.Service.Now(), authenticator.CTime, authenticator.CuSec, this.Service.Settings.MaximumSkew))
            {
                throw new KerberosValidationException($"PKAuthenticator time skew too great");
            }

            this.ValidateNonce(authenticator.Nonce);
        }

        protected virtual void ValidateNonce(int nonce)
        {
            Debug.Assert(nonce != 0);
        }

        private static KrbAuthPack ValidateAuthPack(PreAuthenticationContext preauth, PkInitState state)
        {
            state.Cms.CheckSignature(verifySignatureOnly: true);

            preauth.Principal.Validate(state.Cms.Certificates);

            var authPack = KrbAuthPack.Decode(state.Cms.ContentInfo.Content);

            return authPack;
        }
    }
}
