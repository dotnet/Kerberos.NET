using System;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using Kerberos.NET.Entities;

#pragma warning disable S101 // Types should be named in camel case

namespace Kerberos.NET.Crypto.AES
{
    public abstract class AESTransformer : KerberosCryptoTransformer
    {
        private const int AesBlockSize = 16;

        private static readonly ReadOnlyMemory<byte> AllZerosInitVector = new byte[AesBlockSize];

        private static readonly ReadOnlyMemory<byte> KerberosConstant = Encoding.UTF8.GetBytes("kerberos");

        protected AESTransformer(int keySize)
        {
            KeySize = keySize;
        }

        public override int ChecksumSize => 96 / 8;

        public override int BlockSize => AesBlockSize;

        public int ConfounderSize => BlockSize;

        public override int KeySize { get; }

        public override ReadOnlyMemory<byte> String2Key(KerberosKey key)
        {
            return String2Key(
                key.PasswordBytes,
                AesSalts.GenerateSalt(key),
                key.IterationParameter
            );
        }

        public override ReadOnlyMemory<byte> Encrypt(ReadOnlyMemory<byte> data, KerberosKey kerberosKey, KeyUsage usage)
        {
            var Ke = GetOrDeriveKey(kerberosKey, usage);

            var confounder = GenerateRandomBytes(ConfounderSize);

            var concatLength = confounder.Length + data.Length;

            using (var cleartextPool = CryptoPool.Rent<byte>(concatLength))
            {
                var cleartext = Concat(confounder.Span, data.Span, cleartextPool.Memory.Slice(0, concatLength));

                var encrypted = AESCTS.Encrypt(
                    cleartext,
                    Ke,
                    AllZerosInitVector
                );

                var checksum = MakeChecksum(cleartext, kerberosKey, usage, KeyDerivationMode.Ki, ChecksumSize);

                return Concat(encrypted.Span, checksum.Span);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private ReadOnlyMemory<byte> GetOrDeriveKey(KerberosKey kerberosKey, KeyUsage usage)
        {
            if (kerberosKey == null)
            {
                throw new InvalidOperationException("Key cannot be null");
            }

            return kerberosKey.GetOrDeriveKey(
                this,
                $"{usage}|Ke|{KeySize}|{BlockSize}",
                key => DK(key, usage, KeyDerivationMode.Ke, KeySize, BlockSize)
            );
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ReadOnlyMemory<byte> Concat(ReadOnlySpan<byte> s1, ReadOnlySpan<byte> s2, Memory<byte> array)
        {
            s1.CopyTo(array.Span);
            s2.CopyTo(array.Span.Slice(s1.Length));

            return array;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ReadOnlyMemory<byte> Concat(ReadOnlySpan<byte> s1, ReadOnlySpan<byte> s2)
        {
            return Concat(s1, s2, new Memory<byte>(new byte[s1.Length + s2.Length]));
        }

        public override ReadOnlyMemory<byte> Decrypt(ReadOnlyMemory<byte> cipher, KerberosKey kerberosKey, KeyUsage usage)
        {
            var cipherLength = cipher.Length - ChecksumSize;

            var Ke = GetOrDeriveKey(kerberosKey, usage);

            var decrypted = AESCTS.Decrypt(
                cipher.Slice(0, cipherLength),
                Ke,
                AllZerosInitVector
            );

            var actualChecksum = MakeChecksum(decrypted, kerberosKey, usage, KeyDerivationMode.Ki, ChecksumSize);

            var expectedChecksum = cipher.Slice(cipherLength, ChecksumSize);

            if (!AreEqualSlow(expectedChecksum.Span, actualChecksum.Span))
            {
                throw new SecurityException("Invalid checksum");
            }

            return decrypted.Slice(ConfounderSize, cipherLength - ConfounderSize);
        }

        public override ReadOnlyMemory<byte> MakeChecksum(
            ReadOnlyMemory<byte> data,
            KerberosKey key,
            KeyUsage usage,
            KeyDerivationMode kdf,
            int hashSize
        )
        {
            var ki = key.GetOrDeriveKey(
                this,
                $"{usage}|{kdf}|{KeySize}|{BlockSize}",
                k => DK(k, usage, kdf, KeySize, BlockSize)
            );

            return Hmac(ki, data).Slice(0, hashSize);
        }

        private static ReadOnlyMemory<byte> DK(ReadOnlyMemory<byte> key, KeyUsage usage, KeyDerivationMode kdf, int keySize, int blockSize)
        {
            using (var constantPool = CryptoPool.RentUnsafe<byte>(5))
            {
                var constant = constantPool.Memory.Slice(0, 5);

                Span<byte> span = constant.Span;
                span.Clear();
                BinaryPrimitives.WriteInt32BigEndian(span, (int)usage);

                constant.Span[4] = (byte)kdf;

                return DK(key, constant, keySize, blockSize);
            }
        }

        private static ReadOnlyMemory<byte> DK(ReadOnlyMemory<byte> key, ReadOnlyMemory<byte> constant, int keySize, int blockSize)
        {
            //return Random2Key( DR(...) );

            return DR(key, constant, keySize, blockSize);
        }

        private ReadOnlyMemory<byte> String2Key(byte[] password, string salt, byte[] param)
        {
            var passwordBytes = KerberosConstants.UnicodeBytesToUtf8(password);

            var iterations = GetIterations(param, 4096);

            var saltBytes = KerberosConstants.UnicodeStringToUtf8(salt);

            var random = PBKDF2(passwordBytes, saltBytes, iterations, KeySize);

            return DK(random, KerberosConstant, KeySize, BlockSize);
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

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static int ConvertInt(byte[] bytes, int offset)
        {
            return BinaryPrimitives.ReadInt32BigEndian(bytes.AsSpan(offset));
        }

        private static ReadOnlyMemory<byte> DR(ReadOnlyMemory<byte> key, ReadOnlyMemory<byte> constant, int keySize, int blockSize)
        {
            var keyBytes = new Memory<byte>(new byte[keySize]);

            ReadOnlyMemory<byte> Ki;

            if (constant.Length != blockSize)
            {
                Ki = NFold(constant.Span, blockSize);
            }
            else
            {
                Ki = constant;
            }

            var n = 0;

            do
            {
                Ki = AESCTS.Encrypt(Ki, key, AllZerosInitVector);

                if (n + blockSize >= keySize)
                {
                    Ki.CopyTo(keyBytes.Slice(n, keySize - n));
                    break;
                }

                Ki.CopyTo(keyBytes.Slice(n, blockSize));

                n += blockSize;
            }
            while (n < keySize);

            return keyBytes;
        }

        private static byte[] NFold(ReadOnlySpan<byte> inBytes, int size)
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

        private static ReadOnlyMemory<byte> Hmac(ReadOnlyMemory<byte> key, ReadOnlyMemory<byte> data)
        {
            var hmac = CryptoPal.Platform.HmacSha1();

            return hmac.ComputeHash(key, data);
        }

        private static ReadOnlyMemory<byte> PBKDF2(ReadOnlyMemory<byte> passwordBytes, ReadOnlyMemory<byte> salt, int iterations, int keySize)
        {
            var derivation = CryptoPal.Platform.Rfc2898DeriveBytes();

            return derivation.Derive(passwordBytes, salt, iterations, keySize);
        }
    }
}
