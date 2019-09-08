using System;
using System.Collections.Generic;

namespace Kerberos.NET.Crypto
{
    public static class CryptoService
    {
        private static readonly Dictionary<EncryptionType, Func<KerberosCryptoTransformer>> CryptoAlgorithms
            = new Dictionary<EncryptionType, Func<KerberosCryptoTransformer>>();

        static CryptoService()
        {
            RegisterCryptographicAlgorithm(EncryptionType.RC4_HMAC_NT, () => new RC4Transformer());
            RegisterCryptographicAlgorithm(EncryptionType.RC4_HMAC_NT_EXP, () => new RC4Transformer());

            RegisterCryptographicAlgorithm(EncryptionType.AES128_CTS_HMAC_SHA1_96, () => new AES128Transformer());
            RegisterCryptographicAlgorithm(EncryptionType.AES256_CTS_HMAC_SHA1_96, () => new AES256Transformer());
        }

        public static void RegisterCryptographicAlgorithm(
            EncryptionType type,
            Func<KerberosCryptoTransformer> transformerFunc
        )
        {
            CryptoAlgorithms[type] = transformerFunc;
        }

        public static KerberosCryptoTransformer CreateTransform(EncryptionType etype)
        {
            if (CryptoAlgorithms.TryGetValue(etype, out Func<KerberosCryptoTransformer> func) && func != null)
            {
                return func();
            }

            return null;
        }

        internal static ChecksumType ConvertType(EncryptionType type)
        {
            switch (type)
            {
                case EncryptionType.RC4_HMAC_NT:
                case EncryptionType.RC4_HMAC_NT_EXP:
                case EncryptionType.RC4_HMAC_OLD:
                case EncryptionType.RC4_HMAC_OLD_EXP:
                    return ChecksumType.KERB_CHECKSUM_HMAC_MD5;
                case EncryptionType.AES128_CTS_HMAC_SHA1_96:
                    return ChecksumType.HMAC_SHA1_96_AES128;
                case EncryptionType.AES256_CTS_HMAC_SHA1_96:
                    return ChecksumType.HMAC_SHA1_96_AES256;
                default:
                    throw new InvalidOperationException($"Unknown encryption type {type}");

            }
        }

        internal static KerberosChecksum CreateChecksumValidator(ChecksumType type, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> signatureData)
        {
            switch (type)
            {
                case ChecksumType.KERB_CHECKSUM_HMAC_MD5:
                    return new HmacMd5KerberosChecksum(signature, signatureData);
                case ChecksumType.HMAC_SHA1_96_AES128:
                    return new HmacAes128KerberosChecksum(signature, signatureData);
                case ChecksumType.HMAC_SHA1_96_AES256:
                    return new HmacAes256PacSign(signature, signatureData);
            }

            return null;
        }
    }
}
