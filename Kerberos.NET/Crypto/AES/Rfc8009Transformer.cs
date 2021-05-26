// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Security;
using System.Security.Cryptography;
using System.Text;

namespace Kerberos.NET.Crypto
{
    public abstract class Rfc8009Transformer : AESTransformer
    {
        private static readonly ReadOnlyMemory<byte> DefaultIterations = new ReadOnlyMemory<byte>(new byte[] { 0, 0, 0x80, 0 });

        protected Rfc8009Transformer(int keySize, string encTypeName)
            : base(keySize)
        {
            this.EncTypeName = Encoding.UTF8.GetBytes(encTypeName);
        }

        protected ReadOnlyMemory<byte> EncTypeName { get; }

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

            var encLength = this.EncTypeName.Length;

            var saltp = new Memory<byte>(new byte[encLength + 1 + salt.Length]);

            this.EncTypeName.CopyTo(saltp);

            salt.CopyTo(saltp.Slice(encLength + 1));

            if (param.Length == 0)
            {
                var defaultParam = new byte[4];

                DefaultIterations.CopyTo(defaultParam);

                param = defaultParam;
            }

            return base.String2Key(password, saltp, param);
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

        protected ReadOnlyMemory<byte> Confounder { get; set; }

        public override ReadOnlyMemory<byte> Encrypt(ReadOnlyMemory<byte> data, KerberosKey kerberosKey, KeyUsage usage)
        {
            var Ke = this.GetOrDeriveKey(kerberosKey, usage, KeyDerivationMode.Ke);

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
                var cleartext = Concat(confounder.Span, data.Span, cleartextPool.Memory.Slice(0, concatLength));

                var encrypted = AESCTS.Encrypt(
                    cleartext,
                    Ke,
                    AllZerosInitVector
                );

                var checksumData = Concat(AllZerosInitVector.Span, encrypted.Span);

                var checksum = this.MakeChecksum(checksumData, kerberosKey, usage, KeyDerivationMode.Ki, this.ChecksumSize);

                return Concat(encrypted.Span, checksum.Span);
            }
        }

        public override ReadOnlyMemory<byte> Decrypt(ReadOnlyMemory<byte> cipher, KerberosKey kerberosKey, KeyUsage usage)
        {
            var cipherLength = cipher.Length - this.ChecksumSize;

            var encrypted = cipher.Slice(0, cipherLength);
            var expectedChecksum = cipher.Slice(cipherLength, this.ChecksumSize);

            var checksumData = Concat(AllZerosInitVector.Span, encrypted.Span);

            var actualChecksum = this.MakeChecksum(checksumData, kerberosKey, usage, KeyDerivationMode.Ki, this.ChecksumSize);

            if (!AreEqualSlow(expectedChecksum.Span, actualChecksum.Span))
            {
                throw new SecurityException("Invalid checksum");
            }

            var Ke = this.GetOrDeriveKey(kerberosKey, usage, KeyDerivationMode.Ke);

            var decrypted = AESCTS.Decrypt(
                encrypted,
                Ke,
                AllZerosInitVector
            );

            return decrypted.Slice(this.ConfounderSize, cipherLength - this.ConfounderSize);
        }

        protected override ReadOnlyMemory<byte> DR(ReadOnlyMemory<byte> key, ReadOnlyMemory<byte> constant, int keySize, int blockSize)
        {
            Memory<byte> input = new byte[constant.Length + 9];

            input.Span[3] = 1;

            constant.CopyTo(input.Slice(4));

            IHmacAlgorithm hmac;

            int keyLength;

            if (keySize == 16)
            {
                keyLength = 128;
                hmac = CryptoPal.Platform.HmacSha256(key);
            }
            else
            {
                hmac = CryptoPal.Platform.HmacSha384(key);

                var last = (KeyDerivationMode)constant.Span[constant.Length - 1];

                if (last == KeyDerivationMode.Kc || last == KeyDerivationMode.Ki)
                {
                    keyLength = 192;
                }
                else
                {
                    keyLength = 256;
                }
            }

            input.Span[input.Length - 1] = (byte)keyLength;
            input.Span[input.Length - 2] = (byte)(keyLength / 256);

            return hmac.ComputeHash(input).Slice(0, keySize);
        }

        protected abstract ReadOnlyMemory<byte> Hmac(ReadOnlyMemory<byte> key, ReadOnlyMemory<byte> data);
    }
}
