using Kerberos.NET.Asn1;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.Asn1;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace Kerberos.NET.Server
{
    internal class PaDataPkAsReqHandler : KdcPreAuthenticationHandlerBase
    {
        private static readonly Oid IdPkInitDHKeyData = new Oid("1.3.6.1.5.2.3.2");
        private static readonly Oid DiffieHellman = new Oid("1.2.840.10046.2.1");
        private static readonly Oid EllipticCurveDiffieHellman = new Oid("1.2.840.10045.2.1");

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

            KrbAuthPack authPack = await ValidateAuthPack(preauth.Principal, pkreq);

            ValidateAuthenticator(authPack.PKAuthenticator, asReq.Body);

            var requestAlg = authPack.ClientPublicValue?.Algorithm?.Algorithm;

            IKeyAgreement agreement;

            if (requestAlg?.Value == EllipticCurveDiffieHellman.Value)
            {
                agreement = FromEllipticCurveDomainParameters(authPack.ClientPublicValue);
            }
            else if (requestAlg?.Value == DiffieHellman.Value)
            {
                agreement = FromDiffieHellmanDomainParameters(authPack.ClientPublicValue);
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
            }

            var sessionKey = PKInitString2Key.String2Key(derivedKey.Span, transform.KeySize, clientDHNonce.Span, serverDHNonce.Span);

            preauth.EncryptedPartKey = new KerberosKey(key: sessionKey.ToArray(), etype: etype);

            KrbKdcDHKeyInfo keyInfo = new KrbKdcDHKeyInfo
            {
                SubjectPublicKey = EncodeDiffieHellmanPublicKey(agreement.PublicKey)
            };

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

            return null;
        }

        private async Task<ReadOnlyMemory<byte>> SignDHResponseAsync(KrbKdcDHKeyInfo keyInfo)
        {
            SignedCms signed = new SignedCms(
                new ContentInfo(
                    IdPkInitDHKeyData,
                    keyInfo.Encode().ToArray()
                )
            );

            X509Certificate2 Certificate = await Service.Principals.RetrieveKdcCertificate();

            signed.ComputeSignature(new CmsSigner(Certificate));

            return signed.Encode();
        }

        private static Exception OnlyKeyAgreementSupportedException() => throw new NotSupportedException("Only key agreement is supported for PKINIT authentication");

        private IKeyAgreement FromDiffieHellmanDomainParameters(KrbSubjectPublicKeyInfo clientPublicValue)
        {
            var parameters = KrbDiffieHellmanDomainParameters.DecodeSpecial(clientPublicValue.Algorithm.Parameters.Value);

            IKeyAgreement agreement = DepadLeft(parameters.P).Length switch
            {
                128 => CryptoPal.Platform.DiffieHellmanModp2(),
                256 => CryptoPal.Platform.DiffieHellmanModp14(),
                _ => throw new InvalidOperationException("Unknown key agreement parameter"),
            };

            agreement.ImportPartnerKey(new DiffieHellmanKey
            {
                Public = ParseDiffieHellmanPublicKey(clientPublicValue.SubjectPublicKey)
            });

            return agreement;
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

        private static ReadOnlyMemory<byte> EncodeDiffieHellmanPublicKey(IExchangeKey publicKey)
        {
            using (var writer = new AsnWriter(AsnEncodingRules.DER))
            {
                writer.WriteKeyParameterInteger(publicKey.Public.Span);

                return writer.EncodeAsMemory();
            }
        }

        private static ReadOnlyMemory<byte> ParseDiffieHellmanPublicKey(ReadOnlyMemory<byte> data)
        {
            var reader = new AsnReader(data, AsnEncodingRules.DER);

            var bytes = reader.ReadIntegerBytes().ToArray();

            return bytes;
        }

        private IKeyAgreement FromEllipticCurveDomainParameters(KrbSubjectPublicKeyInfo clientPublicValue)
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
