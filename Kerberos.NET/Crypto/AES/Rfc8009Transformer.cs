// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Security;
using System.Security.Cryptography;

namespace Kerberos.NET.Crypto
{
    public abstract class Rfc8009Transformer : AESTransformer
    {
        protected const int Aes128Sha256KeyLength = 128;
        protected const int Aes256Sha384ChecksumLength = 192;
        protected const int Aes256Sha384KeyLength = 256;

        /// <summary>
        /// Default iteration count is 32768.
        /// </summary>
        private static readonly ReadOnlyMemory<byte> DefaultIterations = new(new byte[] { 0, 0, 0x80, 0 });

        private readonly ReadOnlyMemory<byte> encTypeNameBytes;

        protected Rfc8009Transformer(int keySize, ReadOnlyMemory<byte> encTypeName)
            : base(keySize)
        {
            this.encTypeNameBytes = encTypeName;
        }

        protected ReadOnlyMemory<byte> Confounder { get; set; }

        protected override ReadOnlyMemory<byte> String2Key(ReadOnlyMemory<byte> password, ReadOnlyMemory<byte> salt, ReadOnlyMemory<byte> param)
        {
            /*
             * iter_count = string-to-key parameter, default is decimal 32768
             * saltp = enctype-name | 0x00 | salt
             * tkey = random-to-key(PBKDF2(passphrase, saltp, iter_count, keylength))
             * base-key = random-to-key(KDF-HMAC-SHA2(tkey, "kerberos", keylength))
             *
             * where "kerberos" is the octet-string 0x6B65726265726F73.
             */

            var encLength = this.encTypeNameBytes.Length;

            var saltpLen = encLength + 1 + salt.Length;

            using (var saltpRented = CryptoPool.Rent<byte>(saltpLen))
            {
                var saltp = saltpRented.Memory.Slice(0, saltpLen);

                this.encTypeNameBytes.CopyTo(saltp);

                salt.CopyTo(saltp.Slice(encLength + 1));

                var iterationsLen = param.Length == 0 ? 4 : param.Length;

                using (var iterationsRented = CryptoPool.Rent<byte>(iterationsLen))
                {
                    var iterations = iterationsRented.Memory.Slice(0, iterationsLen);

                    if (param.Length == 0)
                    {
                        DefaultIterations.CopyTo(iterations);
                    }
                    else
                    {
                        param.CopyTo(iterations);
                    }

                    return base.String2Key(password, saltp, iterations);
                }
            }
        }

        public override ReadOnlyMemory<byte> MakeChecksum(
            ReadOnlyMemory<byte> data,
            KerberosKey key,
            KeyUsage usage,
            KeyDerivationMode kdf,
            int hashSize
        )
        {
            var ki = this.GetOrDeriveKey(key, usage, kdf).Slice(0, hashSize);

            return this.Hmac(ki, data).Slice(0, hashSize);
        }

        public override ReadOnlyMemory<byte> Encrypt(ReadOnlyMemory<byte> data, KerberosKey kerberosKey, KeyUsage usage)
        {
            var ke = this.GetOrDeriveKey(kerberosKey, usage, KeyDerivationMode.Ke);

            ReadOnlyMemory<byte> confounder;

            if (this.Confounder.Length > 0)
            {
                confounder = this.Confounder;
            }
            else
            {
                confounder = this.GenerateRandomBytes(this.ConfounderSize);
            }

            var concatLength = confounder.Length + data.Length;

            using (var cleartextPool = CryptoPool.Rent<byte>(concatLength))
            {
                var cleartext = cleartextPool.Memory.Slice(0, concatLength);

                Concat(confounder.Span, data.Span, cleartext);

                var encrypted = AESCTS.Encrypt(
                    cleartext,
                    ke,
                    AllZerosInitVector
                );

                var checksumDataLength = AllZerosInitVector.Length + encrypted.Length;

                using (var checksumDataRented = CryptoPool.Rent<byte>(checksumDataLength))
                {
                    var checksumData = checksumDataRented.Memory.Slice(0, checksumDataLength);

                    Concat(AllZerosInitVector.Span, encrypted.Span, checksumData);

                    var checksum = this.MakeChecksum(checksumData, kerberosKey, usage, KeyDerivationMode.Ki, this.ChecksumSize);

                    return Concat(encrypted.Span, checksum.Span);
                }
            }
        }

        public override ReadOnlyMemory<byte> Decrypt(ReadOnlyMemory<byte> cipher, KerberosKey kerberosKey, KeyUsage usage)
        {
            var cipherLength = cipher.Length - this.ChecksumSize;

            var encrypted = cipher.Slice(0, cipherLength);
            var expectedChecksum = cipher.Slice(cipherLength, this.ChecksumSize);

            var checksumDataLength = AllZerosInitVector.Length + encrypted.Length;

            using (var checksumDataRented = CryptoPool.Rent<byte>(checksumDataLength))
            {
                var checksumData = checksumDataRented.Memory.Slice(0, checksumDataLength);

                Concat(AllZerosInitVector.Span, encrypted.Span, checksumData);

                var actualChecksum = this.MakeChecksum(checksumData, kerberosKey, usage, KeyDerivationMode.Ki, this.ChecksumSize);

                if (!AreEqualSlow(expectedChecksum.Span, actualChecksum.Span))
                {
                    throw new SecurityException("Invalid checksum");
                }
            }

            var ke = this.GetOrDeriveKey(kerberosKey, usage, KeyDerivationMode.Ke);

            var decrypted = AESCTS.Decrypt(
                encrypted,
                ke,
                AllZerosInitVector
            );

            return decrypted.Slice(this.ConfounderSize, cipherLength - this.ConfounderSize);
        }

        protected override ReadOnlyMemory<byte> DR(ReadOnlyMemory<byte> key, ReadOnlyMemory<byte> constant, int keySize, int blockSize)
        {
            /* derivation uses SP800-108 5.1 Counter mode
             * K1 = HMAC-SHA-256(key, 0x00000001 | label | 0x00 | k)
             *
             * k: Length in bits of the key to be outputted, expressed in big-endian binary representation in 4 bytes.
             * Specifically, k=128 is represented as 0x00000080, 192 as 0x000000C0, 256 as 0x00000100, and 384 as 0x00000180.
             */

            int k;
            HashAlgorithmName algName;

            if (keySize == 16)
            {
                k = Aes128Sha256KeyLength;
                algName = HashAlgorithmName.SHA256;
            }
            else
            {
                algName = HashAlgorithmName.SHA384;

                var last = (KeyDerivationMode)constant.Span[constant.Length - 1];

                if (last == KeyDerivationMode.Kc || last == KeyDerivationMode.Ki)
                {
                    k = Aes256Sha384ChecksumLength;
                }
                else
                {
                    k = Aes256Sha384KeyLength;
                }
            }

            var sp800 = CryptoPal.Platform.SP800108CounterMode();

            return sp800.Derive(algName, key, constant, k, keySize);
        }

        protected abstract ReadOnlyMemory<byte> Hmac(ReadOnlyMemory<byte> key, ReadOnlyMemory<byte> data);
    }
}
