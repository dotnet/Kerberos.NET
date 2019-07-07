﻿using System;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Text;

#pragma warning disable S101 // Types should be named in camel case

namespace Kerberos.NET.Crypto.AES
{
    public abstract class AESTransformer : KerberosCryptoTransformer
    {
        private const int AesBlockSize = 16;

        private static readonly byte[] AllZerosInitVector = new byte[AesBlockSize];

        private static readonly byte[] KerberosConstant = Encoding.UTF8.GetBytes("kerberos");

        protected AESTransformer(int keySize)
        {
            KeySize = keySize;
        }

        public override int ChecksumSize => 96 / 8;

        public override int BlockSize => AesBlockSize;

        public int ConfounderSize => BlockSize;

        public override int KeySize { get; }

        public override byte[] String2Key(KerberosKey key)
        {
            return String2Key(
                key.PasswordBytes,
                AesSalts.GenerateSalt(key),
                key.IterationParameter
            );
        }

        public override ReadOnlyMemory<byte> Encrypt(ReadOnlySpan<byte> data, KerberosKey kerberosKey, KeyUsage usage)
        {
            var key = kerberosKey.GetKey(this);

            var Ke = DK(key, usage, KeyDerivationMode.Ke);

            var cleartext = new Span<byte>(new byte[ConfounderSize + data.Length]);

            var confounder = GenerateRandomBytes(ConfounderSize);

            confounder.CopyTo(cleartext.Slice(0, ConfounderSize));
            data.CopyTo(cleartext.Slice(ConfounderSize, data.Length));

            var encrypted = AESCTS.Encrypt(
                cleartext.ToArray(),
                Ke,
                AllZerosInitVector
            );

            var checksum = MakeChecksum(key, usage, KeyDerivationMode.Ki, cleartext.ToArray(), ChecksumSize);

            return new ReadOnlyMemory<byte>(encrypted.Concat(checksum).ToArray());
        }

        public override byte[] Decrypt(ReadOnlyMemory<byte> cipher, KerberosKey kerberosKey, KeyUsage usage)
        {
            var key = kerberosKey.GetKey(this);

            var cipherLength = cipher.Length - ChecksumSize;

            var Ke = DK(key, usage, KeyDerivationMode.Ke);

            var decrypted = AESCTS.Decrypt(
                BlockCopy(cipher, 0, cipherLength),
                Ke,
                AllZerosInitVector
            );

            var actualChecksum = MakeChecksum(key, usage, KeyDerivationMode.Ki, decrypted, ChecksumSize);

            var expectedChecksum = BlockCopy(cipher, cipherLength, ChecksumSize);

            if (!AreEqualSlow(expectedChecksum, actualChecksum))
            {
                throw new SecurityException("Invalid checksum");
            }

            return BlockCopy(decrypted, ConfounderSize, cipherLength - ConfounderSize);
        }

        public override byte[] MakeChecksum(byte[] key, KeyUsage usage, KeyDerivationMode kdf, byte[] data, int hashSize)
        {
            var ki = DK(key, usage, kdf);

            var hash = Hmac(ki, data);

            var output = new byte[hashSize];

            Buffer.BlockCopy(hash, 0, output, 0, hashSize);

            return output;
        }

        private static byte[] BlockCopy(ReadOnlyMemory<byte> src, int srcOffset, int len)
        {
            var tmpEnc = new byte[len];

            Buffer.BlockCopy(src.ToArray(), srcOffset, tmpEnc, 0, len);

            return tmpEnc;
        }

        private byte[] DK(byte[] key, KeyUsage usage, KeyDerivationMode kdf)
        {
            var constant = new byte[5];

            Endian.ConvertToBigEndian((int)usage, constant, 0);

            constant[4] = (byte)kdf;

            return DK(key, constant);
        }

        private byte[] DK(byte[] key, byte[] constant)
        {
            return Random2Key(
                DR(key, constant)
            );
        }

        private byte[] String2Key(byte[] password, string salt, byte[] param)
        {
            var passwordBytes = UnicodeBytesToUtf8(password);

            var iterations = GetIterations(param, 4096);

            var saltBytes = GetSaltBytes(salt, null);

            var random = PBKDF2(passwordBytes, saltBytes, iterations, KeySize);

            var tmpKey = Random2Key(random);

            return DK(tmpKey, KerberosConstant);
        }

        private static byte[] UnicodeBytesToUtf8(byte[] str)
        {
            return Encoding.Convert(Encoding.Unicode, Encoding.UTF8, str, 0, str.Length);
        }

        private static byte[] UnicodeStringToUtf8(string salt)
        {
            return UnicodeBytesToUtf8(Encoding.Unicode.GetBytes(salt));
        }

        private static byte[] PBKDF2(byte[] passwordBytes, byte[] salt, int iterations, int keySize)
        {
            using (var derive = new Rfc2898DeriveBytes(passwordBytes, salt, iterations))
            {
                return derive.GetBytes(keySize);
            }
        }

        private static int GetIterations(byte[] param, int defCount)
        {
            int iterCount = defCount;

            if (param != null)
            {
                if (param.Length % 4 != 0)
                {
                    throw new ArgumentException("Invalid param to str2Key");
                }

                iterCount = ConvertInt(param, param.Length - 4);
            }

            if (iterCount == 0)
            {
                iterCount = int.MaxValue;
            }

            return iterCount;
        }

        private static int ConvertInt(byte[] bytes, int offset)
        {
            var val = 0;

            val += (bytes[offset + 0] & 0xff) << 24;
            val += (bytes[offset + 1] & 0xff) << 16;
            val += (bytes[offset + 2] & 0xff) << 8;
            val += (bytes[offset + 3] & 0xff);

            return val;
        }

        private static byte[] GetSaltBytes(string salt, string pepper)
        {
            var saltBytes = UnicodeStringToUtf8(salt);

            if (string.IsNullOrWhiteSpace(pepper))
            {
                return saltBytes;
            }

            var pepperBytes = UnicodeStringToUtf8(pepper);

            var length = saltBytes.Length + 1 + pepperBytes.Length;

            var results = new byte[length];

            Buffer.BlockCopy(pepperBytes, 0, results, 0, pepperBytes.Length);

            results[pepperBytes.Length] = 0;

            Buffer.BlockCopy(saltBytes, 0, results, pepperBytes.Length + 1, saltBytes.Length);

            return results;
        }

        private byte[] DR(byte[] key, byte[] constant)
        {
            var keyBytes = new byte[KeySize];

            byte[] Ki;

            if (constant.Length != BlockSize)
            {
                Ki = NFold(constant, BlockSize);
            }
            else
            {
                Ki = new byte[constant.Length];
                Buffer.BlockCopy(constant, 0, Ki, 0, constant.Length);
            }

            var n = 0;

            do
            {
                Ki = AESCTS.Encrypt(Ki, key, AllZerosInitVector);

                if (n + BlockSize >= KeySize)
                {
                    Buffer.BlockCopy(Ki, 0, keyBytes, n, KeySize - n);
                    break;
                }

                Buffer.BlockCopy(Ki, 0, keyBytes, n, BlockSize);

                n += BlockSize;
            }
            while (n < KeySize);

            return keyBytes;
        }

        private static byte[] NFold(byte[] inBytes, int size)
        {
            var inBytesSize = inBytes.Length;
            var outBytesSize = size;

            var a = outBytesSize;
            var b = inBytesSize;

            while (b != 0)
            {
                var c = b;
                b = a % b;
                a = c;
            }

            var lcm = (outBytesSize * inBytesSize) / a;

            var outBytes = new byte[outBytesSize];

            var tmpByte = 0;

            for (var i = lcm - 1; i >= 0; i--)
            {
                var msbit = (inBytesSize << 3) - 1;

                msbit += ((inBytesSize << 3) + 13) * (i / inBytesSize);
                msbit += (inBytesSize - (i % inBytesSize)) << 3;
                msbit %= inBytesSize << 3;

                var rst = inBytes[(inBytesSize - 1 - (msbit >> 3)) % inBytesSize] & 0xff;
                var rst2 = inBytes[(inBytesSize - (msbit >> 3)) % inBytesSize] & 0xff;

                msbit = (((rst << 8) | (rst2)) >> ((msbit & 7) + 1)) & 0xff;

                tmpByte += msbit;
                msbit = outBytes[i % outBytesSize] & 0xff;
                tmpByte += msbit;

                outBytes[i % outBytesSize] = (byte)(tmpByte & 0xff);

                tmpByte >>= 8;
            }

            if (tmpByte != 0)
            {
                for (var i = outBytesSize - 1; i >= 0; i--)
                {
                    tmpByte += outBytes[i] & 0xff;
                    outBytes[i] = (byte)(tmpByte & 0xff);

                    tmpByte >>= 8;
                }
            }

            return outBytes;
        }

        private static byte[] Hmac(byte[] key, byte[] data)
        {
            using (var hmac = new HMACSHA1(key))
            {
                return hmac.ComputeHash(data);
            }
        }
    }
}
