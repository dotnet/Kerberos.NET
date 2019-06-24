using Kerberos.NET.Entities;
using System;
using System.Collections.Generic;

namespace Kerberos.NET.Crypto
{
    public static class CryptographyService
    {
        private static readonly Dictionary<EncryptionType, Func<KerberosCryptoTransformer>> CryptoAlgorithms
            = new Dictionary<EncryptionType, Func<KerberosCryptoTransformer>>();

        static CryptographyService()
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

        public static KerberosCryptoTransformer CreateDecryptor(EncryptionType etype)
        {
            if (CryptoAlgorithms.TryGetValue(etype, out Func<KerberosCryptoTransformer> func) && func != null)
            {
                return func();
            }

            return null;
        }

        internal static PacValidator CreateChecksumValidator(ChecksumType type, byte[] signature, byte[] signatureData)
        {
            switch (type)
            {
                case ChecksumType.KERB_CHECKSUM_HMAC_MD5:
                    return new HmacMd5PacValidator(signature, signatureData);
                case ChecksumType.HMAC_SHA1_96_AES128:
                    return new HmacAes128PacValidator(signature, signatureData);
                case ChecksumType.HMAC_SHA1_96_AES256:
                    return new HmacAes256PacValidator(signature, signatureData);
            }

            return null;
        }
    }
}
