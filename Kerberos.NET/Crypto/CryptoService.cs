// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using ChecksumConstructor = System.Func<System.ReadOnlyMemory<byte>, System.ReadOnlyMemory<byte>, Kerberos.NET.Crypto.KerberosChecksum>;

namespace Kerberos.NET.Crypto
{
    public static class CryptoService
    {
        private static readonly ConcurrentDictionary<EncryptionType, Func<KerberosCryptoTransformer>> CryptoAlgorithms
            = new ConcurrentDictionary<EncryptionType, Func<KerberosCryptoTransformer>>();

        private static readonly ConcurrentDictionary<ChecksumType, ChecksumConstructor> ChecksumAlgorithms
            = new ConcurrentDictionary<ChecksumType, ChecksumConstructor>();

        private static readonly ConcurrentDictionary<EncryptionType, ChecksumType> ETypeToChecksumCache
            = new ConcurrentDictionary<EncryptionType, ChecksumType>();

        private static readonly HashSet<EncryptionType> WeakEncryptionTypes = new HashSet<EncryptionType>();

        private static readonly HashSet<ChecksumType> WeakChecksumTypes = new HashSet<ChecksumType>();

        static CryptoService()
        {
#if WEAKCRYPTO
            RegisterCryptographicAlgorithm(
                EncryptionType.RC4_HMAC_NT,
                () => new RC4Transformer(),
                isWeakAlgorithm: true
            );

            RegisterCryptographicAlgorithm(
                EncryptionType.RC4_HMAC_NT_EXP,
                () => new RC4Transformer(),
                isWeakAlgorithm: true
            );

            RegisterChecksumAlgorithm(
                ChecksumType.KERB_CHECKSUM_HMAC_MD5,
                (signature, signatureData) => new HmacMd5KerberosChecksum(signature, signatureData),
                isWeakAlgorithm: true
            );
#endif
            RegisterCryptographicAlgorithm(EncryptionType.AES128_CTS_HMAC_SHA1_96, () => new AES128Transformer());
            RegisterCryptographicAlgorithm(EncryptionType.AES256_CTS_HMAC_SHA1_96, () => new AES256Transformer());
            RegisterCryptographicAlgorithm(EncryptionType.AES128_CTS_HMAC_SHA256_128, () => new AES128Sha256Transformer());
            RegisterCryptographicAlgorithm(EncryptionType.AES256_CTS_HMAC_SHA384_192, () => new AES256Sha384Transformer());

            RegisterChecksumAlgorithm(ChecksumType.HMAC_SHA1_96_AES128, (signature, signatureData) => new HmacAes128KerberosChecksum(signature, signatureData));
            RegisterChecksumAlgorithm(ChecksumType.HMAC_SHA1_96_AES256, (signature, signatureData) => new HmacAes256KerberosChecksum(signature, signatureData));
            RegisterChecksumAlgorithm(ChecksumType.HMAC_SHA256_128_AES128, (signature, signatureData) => new HmacAes128Sha256KerberosChecksum(signature, signatureData));
            RegisterChecksumAlgorithm(ChecksumType.HMAC_SHA384_192_AES256, (signature, signatureData) => new HmacAes256Sha384KerberosChecksum(signature, signatureData));
        }

        public static void RegisterCryptographicAlgorithm(
            EncryptionType type,
            Func<KerberosCryptoTransformer> transformerFunc
        )
        {
            RegisterCryptographicAlgorithm(type, transformerFunc, isWeakAlgorithm: false);
        }

        public static void RegisterCryptographicAlgorithm(
            EncryptionType type,
            Func<KerberosCryptoTransformer> transformerFunc,
            bool isWeakAlgorithm
        )
        {
            CryptoAlgorithms[type] = transformerFunc;

            if (isWeakAlgorithm)
            {
                WeakEncryptionTypes.Add(type);
            }
        }

        public static void RegisterChecksumAlgorithm(
            ChecksumType type,
            ChecksumConstructor checksumFunc,
            bool isWeakAlgorithm
        )
        {
            ChecksumAlgorithms[type] = checksumFunc;

            if (isWeakAlgorithm)
            {
                WeakChecksumTypes.Add(type);
            }
        }

        public static void RegisterChecksumAlgorithm(
            ChecksumType type,
            ChecksumConstructor checksumFunc
        )
        {
            RegisterChecksumAlgorithm(type, checksumFunc, isWeakAlgorithm: false);
        }

        public static void UnregisterCryptographicAlgorithm(EncryptionType encryptionType)
        {
            CryptoAlgorithms.TryRemove(encryptionType, out _);
        }

        public static void UnregisterChecksumAlgorithm(ChecksumType checksumType)
        {
            ChecksumAlgorithms.TryRemove(checksumType, out _);
        }

        public static KerberosCryptoTransformer CreateTransform(EncryptionType etype)
        {
            if (CryptoAlgorithms.TryGetValue(etype, out Func<KerberosCryptoTransformer> func) && func != null)
            {
                return func();
            }

            return null;
        }

        public static bool SupportsEType(EncryptionType etype, bool allowWeakCrypto)
        {
            if (!allowWeakCrypto && WeakEncryptionTypes.Contains(etype))
            {
                return false;
            }

            return CryptoAlgorithms.ContainsKey(etype);
        }

        public static bool SupportsEType(EncryptionType etype) => SupportsEType(etype, allowWeakCrypto: false);

        internal static ChecksumType ConvertType(EncryptionType type)
        {
            if (ETypeToChecksumCache.TryGetValue(type, out ChecksumType checksumType))
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

            ETypeToChecksumCache.TryAdd(type, checksumType);

            return checksumType;
        }

        public static KerberosChecksum CreateChecksum(
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
