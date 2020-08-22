// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using ChecksumConstructor = System.Func<System.ReadOnlyMemory<byte>, System.ReadOnlyMemory<byte>, Kerberos.NET.Crypto.KerberosChecksum>;

namespace Kerberos.NET.Crypto
{
    public static class CryptoService
    {
        private static readonly Dictionary<EncryptionType, Func<KerberosCryptoTransformer>> CryptoAlgorithms
            = new Dictionary<EncryptionType, Func<KerberosCryptoTransformer>>();

        private static readonly Dictionary<ChecksumType, ChecksumConstructor> ChecksumAlgorithms
            = new Dictionary<ChecksumType, ChecksumConstructor>();

        static CryptoService()
        {
#if WEAKCRYPTO
            RegisterCryptographicAlgorithm(EncryptionType.RC4_HMAC_NT, () => new RC4Transformer());
            RegisterCryptographicAlgorithm(EncryptionType.RC4_HMAC_NT_EXP, () => new RC4Transformer());
            RegisterChecksumAlgorithm(ChecksumType.KERB_CHECKSUM_HMAC_MD5, (signature, signatureData) => new HmacMd5KerberosChecksum(signature, signatureData));
#endif
            RegisterCryptographicAlgorithm(EncryptionType.AES128_CTS_HMAC_SHA1_96, () => new AES128Transformer());
            RegisterCryptographicAlgorithm(EncryptionType.AES256_CTS_HMAC_SHA1_96, () => new AES256Transformer());

            RegisterChecksumAlgorithm(ChecksumType.HMAC_SHA1_96_AES128, (signature, signatureData) => new HmacAes128KerberosChecksum(signature, signatureData));
            RegisterChecksumAlgorithm(ChecksumType.HMAC_SHA1_96_AES256, (signature, signatureData) => new HmacAes256KerberosChecksum(signature, signatureData));
        }

        public static void RegisterCryptographicAlgorithm(
            EncryptionType type,
            Func<KerberosCryptoTransformer> transformerFunc
        )
        {
            CryptoAlgorithms[type] = transformerFunc;
        }

        public static void RegisterChecksumAlgorithm(
            ChecksumType type,
            ChecksumConstructor checksumFunc
        )
        {
            ChecksumAlgorithms[type] = checksumFunc;
        }

        public static void UnregisterCryptographicAlgorithm(EncryptionType encryptionType)
        {
            CryptoAlgorithms.Remove(encryptionType);
        }

        public static void UnregisterChecksumAlgorithm(ChecksumType checksumType)
        {
            ChecksumAlgorithms.Remove(checksumType);
        }

        public static KerberosCryptoTransformer CreateTransform(EncryptionType etype)
        {
            if (CryptoAlgorithms.TryGetValue(etype, out Func<KerberosCryptoTransformer> func) && func != null)
            {
                return func();
            }

            return null;
        }

        public static bool SupportsEType(EncryptionType etype)
        {
            return CryptoAlgorithms.ContainsKey(etype);
        }

        private static readonly Dictionary<EncryptionType, ChecksumType> Cache = new Dictionary<EncryptionType, ChecksumType>();

        internal static ChecksumType ConvertType(EncryptionType type)
        {
            if (Cache.TryGetValue(type, out ChecksumType checksumType))
            {
                return checksumType;
            }

            switch (type)
            {
                case EncryptionType.RC4_HMAC_NT:
                case EncryptionType.RC4_HMAC_NT_EXP:
                case EncryptionType.RC4_HMAC_OLD:
                case EncryptionType.RC4_HMAC_OLD_EXP:
                    checksumType = ChecksumType.KERB_CHECKSUM_HMAC_MD5;
                    break;
                case EncryptionType.AES128_CTS_HMAC_SHA1_96:
                    checksumType = ChecksumType.HMAC_SHA1_96_AES128;
                    break;
                case EncryptionType.AES256_CTS_HMAC_SHA1_96:
                    checksumType = ChecksumType.HMAC_SHA1_96_AES256;
                    break;
                default:
                    var transform = CreateTransform(type);

                    if (transform == null)
                    {
                        throw new InvalidOperationException($"Unknown encryption type {type}");
                    }

                    checksumType = transform.ChecksumType;
                    break;
            }

            Cache[type] = checksumType;

            return checksumType;
        }

        internal static KerberosChecksum CreateChecksum(
            ChecksumType type,
            ReadOnlyMemory<byte> signature = default,
            ReadOnlyMemory<byte> signatureData = default
        )
        {
            if (ChecksumAlgorithms.TryGetValue(type, out ChecksumConstructor func) && func != null)
            {
                return func(signature, signatureData);
            }

            return null;
        }
    }
}