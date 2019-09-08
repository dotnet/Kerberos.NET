using System;
using System.Runtime.CompilerServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;

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

        public override ReadOnlySpan<byte> String2Key(KerberosKey key)
        {
            return String2Key(
                key.PasswordBytes,
                AesSalts.GenerateSalt(key),
                key.IterationParameter
            );
        }

        public override ReadOnlyMemory<byte> Encrypt(ReadOnlyMemory<byte> data, KerberosKey kerberosKey, KeyUsage usage)
        {
            var Ke = kerberosKey.GetOrDeriveKey(
                this,
                $"{usage}|Ke|{KeySize}|{BlockSize}",
                key => DK(key.Span, usage, KeyDerivationMode.Ke, KeySize, BlockSize).AsMemory()
            );

            var confounder = GenerateRandomBytes(ConfounderSize);

            var cleartext = Concat(confounder.Span, data.Span);

            var encrypted = AESCTS.Encrypt(
                cleartext.Span,
                Ke,
                AllZerosInitVector.Span
            );

            var checksum = MakeChecksum(cleartext.Span, kerberosKey, usage, KeyDerivationMode.Ki, ChecksumSize);

            return Concat(encrypted, checksum);
        }

        private static ReadOnlyMemory<byte> Concat(ReadOnlySpan<byte> s1, ReadOnlySpan<byte> s2)
        {
            var array = new byte[s1.Length + s2.Length];
            s1.CopyTo(array);
            s2.CopyTo(array.AsSpan(s1.Length));
            return array;
        }

        public override ReadOnlySpan<byte> Decrypt(ReadOnlyMemory<byte> cipher, KerberosKey kerberosKey, KeyUsage usage)
        {
            var cipherLength = cipher.Length - ChecksumSize;

            var Ke = kerberosKey.GetOrDeriveKey(
                this,
                $"{usage}|Ke|{KeySize}|{BlockSize}",
                key => DK(key.Span, usage, KeyDerivationMode.Ke, KeySize, BlockSize).AsMemory()
            );

            var decrypted = AESCTS.Decrypt(
                cipher.Span.Slice(0, cipherLength),
                Ke,
                AllZerosInitVector.Span
            );

            var actualChecksum = MakeChecksum(decrypted, kerberosKey, usage, KeyDerivationMode.Ki, ChecksumSize);

            var expectedChecksum = cipher.Slice(cipherLength, ChecksumSize);

            if (!AreEqualSlow(expectedChecksum.Span, actualChecksum))
            {
                throw new SecurityException("Invalid checksum");
            }

            return decrypted.Slice(ConfounderSize, cipherLength - ConfounderSize);
        }

        public override ReadOnlySpan<byte> MakeChecksum(
            ReadOnlySpan<byte> data,
            KerberosKey key,
            KeyUsage usage,
            KeyDerivationMode kdf,
            int hashSize
        )
        {
            var ki = key.GetOrDeriveKey(
                this,
                $"{usage}|{kdf}|{KeySize}|{BlockSize}",
                k => DK(k.Span, usage, kdf, KeySize, BlockSize).AsMemory()
            );

            return Hmac(ki, data).Slice(0, hashSize);
        }

        private static ReadOnlySpan<byte> DK(ReadOnlySpan<byte> key, KeyUsage usage, KeyDerivationMode kdf, int keySize, int blockSize)
        {
            var constant = new Span<byte>(new byte[5]);

            Endian.ConvertToBigEndian((int)usage, constant);

            constant[4] = (byte)kdf;

            return DK(key, constant, keySize, blockSize);
        }

        private static ReadOnlySpan<byte> DK(ReadOnlySpan<byte> key, ReadOnlySpan<byte> constant, int keySize, int blockSize)
        {
            //return Random2Key( DR(...) );

            return DR(key, constant, keySize, blockSize);
        }

        private ReadOnlySpan<byte> String2Key(byte[] password, string salt, byte[] param)
        {
            var passwordBytes = UnicodeBytesToUtf8(password);

            var iterations = GetIterations(param, 4096);

            var saltBytes = GetSaltBytes(salt, null);

            var random = PBKDF2(passwordBytes, saltBytes, iterations, KeySize);

            var tmpKey = Random2Key(random);

            return DK(tmpKey, KerberosConstant.Span, KeySize, BlockSize);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ReadOnlySpan<byte> UnicodeBytesToUtf8(byte[] str)
        {
            return Encoding.Convert(Encoding.Unicode, Encoding.UTF8, str, 0, str.Length);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ReadOnlySpan<byte> UnicodeStringToUtf8(string salt)
        {
            return UnicodeBytesToUtf8(Encoding.Unicode.GetBytes(salt));
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
            var val = 0;

            val += (bytes[offset + 0] & 0xff) << 24;
            val += (bytes[offset + 1] & 0xff) << 16;
            val += (bytes[offset + 2] & 0xff) << 8;
            val += (bytes[offset + 3] & 0xff);

            return val;
        }

        private static ReadOnlySpan<byte> GetSaltBytes(string salt, string pepper)
        {
            var saltBytes = UnicodeStringToUtf8(salt);

            if (string.IsNullOrWhiteSpace(pepper))
            {
                return saltBytes;
            }

            var pepperBytes = UnicodeStringToUtf8(pepper);
            
            var results = new Span<byte>(new byte[saltBytes.Length + 1 + pepperBytes.Length]);

            pepperBytes.CopyTo(results);

            saltBytes.CopyTo(results.Slice(pepperBytes.Length + 1, saltBytes.Length));

            return results;
        }

        private static ReadOnlySpan<byte> DR(ReadOnlySpan<byte> key, ReadOnlySpan<byte> constant, int keySize, int blockSize)
        {
            var keyBytes = new Span<byte>(new byte[keySize]);

            ReadOnlySpan<byte> Ki;

            if (constant.Length != blockSize)
            {
                Ki = NFold(constant, blockSize);
            }
            else
            {
                Ki = constant.Slice(0);
            }

            var n = 0;

            do
            {
                Ki = AESCTS.Encrypt(Ki, key, AllZerosInitVector.Span);

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

        private static ReadOnlySpan<byte> Hmac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data)
        {
            using (var hmac = new HMACSHA1(key.ToArray()))
            {
                return hmac.ComputeHash(data.ToArray());
            }
        }

        private static ReadOnlySpan<byte> PBKDF2(ReadOnlySpan<byte> passwordBytes, ReadOnlySpan<byte> salt, int iterations, int keySize)
        {
            using (var derive = new Rfc2898DeriveBytes(passwordBytes.ToArray(), salt.ToArray(), iterations))
            {
                return derive.GetBytes(keySize);
            }
        }
    }
}
