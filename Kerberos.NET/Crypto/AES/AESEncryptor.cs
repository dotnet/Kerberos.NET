using System;
using System.Security.Cryptography;
using System.Text;

#pragma warning disable S101 // Types should be named in camel case

namespace Kerberos.NET.Crypto
{
    public abstract class AESEncryptor : IEncryptor
    {
        private readonly int blockSize;
        private readonly int keyInputSize;
        private readonly int keySize;

        protected AESEncryptor(int blockSize, int keyInputSize, int keySize)
        {
            this.blockSize = blockSize;
            this.keyInputSize = keyInputSize;
            this.keySize = keySize;
        }

        public int BlockSize { get { return blockSize; } }

        public int KeyInputSize { get { return keyInputSize; } }

        public int KeySize { get { return keySize; } }

        public void Decrypt(byte[] key, byte[] iv, byte[] tmpEnc)
        {
            var output = AESCTS.Decrypt(tmpEnc, key, iv);

            Buffer.BlockCopy(output, 0, tmpEnc, 0, output.Length);
        }

        public void Encrypt(byte[] key, byte[] ki)
        {
            var cipherState = new byte[BlockSize];

            Encrypt(key, cipherState, ki);
        }

        public void Encrypt(byte[] key, byte[] iv, byte[] tmpEnc)
        {
            var output = AESCTS.Encrypt(tmpEnc, key, iv);

            Buffer.BlockCopy(output, 0, tmpEnc, 0, output.Length);
        }

        public byte[] String2Key(KerberosKey key)
        {
            return String2Key(key.Password, GenerateSalt(key), null);
        }

        private static string GenerateSalt(KerberosKey key)
        {
            var salt = new StringBuilder();

            if (key.PrincipalName == null)
            {
                return salt.ToString();
            }

            salt.Append(key.PrincipalName.Realm);

            salt.Append("host");
            salt.Append(key.Host);
            salt.Append(".");
            salt.Append(key.PrincipalName.Realm.ToLowerInvariant());

            return salt.ToString();
        }

        private static readonly byte[] KerberosConstant = Encoding.UTF8.GetBytes("kerberos");

        private byte[] String2Key(string key, string salt, byte[] param)
        {
            var passwordBytes = Encoding.UTF8.GetBytes(key);

            var iterations = GetIterations(param, 4096);

            var saltBytes = GetSaltBytes(salt, null);
            
            var random = PBKDF2(passwordBytes, saltBytes, iterations, KeySize);

            var tmpKey = Random2Key(random);

            return DK(tmpKey, KerberosConstant);
        }

        private static byte[] PBKDF2(byte[] passwordBytes, byte[] salt, int iterations, int keySize)
        {
            var derive = new Rfc2898DeriveBytes(passwordBytes, salt, iterations);

            return derive.GetBytes(keySize);
        }

        protected static int GetIterations(byte[] param, int defCount)
        {
            int iterCount = defCount;

            if (param != null)
            {
                if (param.Length != 4)
                {
                    throw new ArgumentException("Invalid param to str2Key");
                }

                iterCount = ConvertInt(param, 0);
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

        protected static byte[] GetSaltBytes(string salt, string pepper)
        {
            var saltBytes = Encoding.UTF8.GetBytes(salt);

            if (string.IsNullOrWhiteSpace(pepper))
            {
                return saltBytes;
            }

            var pepperBytes = Encoding.UTF8.GetBytes(pepper);

            var length = saltBytes.Length + 1 + pepperBytes.Length;

            var results = new byte[length];

            Buffer.BlockCopy(pepperBytes, 0, results, 0, pepperBytes.Length);

            results[pepperBytes.Length] = 0;

            Buffer.BlockCopy(saltBytes, 0, results, pepperBytes.Length + 1, saltBytes.Length);

            return results;
        }

        protected virtual byte[] Random2Key(byte[] randomBits)
        {
            return randomBits;
        }

        public byte[] DK(byte[] key, byte[] constant)
        {
            return Random2Key(DR(key, constant));
        }

        protected byte[] DR(byte[] key, byte[] constant)
        {
            var blocksize = BlockSize;
            var keyInuptSize = KeyInputSize;

            var keyBytes = new byte[keyInuptSize];

            byte[] Ki;

            if (constant.Length != blocksize)
            {
                Ki = NFold(constant, blocksize);
            }
            else
            {
                Ki = new byte[constant.Length];
                Buffer.BlockCopy(constant, 0, Ki, 0, constant.Length);
            }

            var n = 0;

            do
            {
                Encrypt(key, Ki);

                if (n + blocksize >= keyInuptSize)
                {
                    Buffer.BlockCopy(Ki, 0, keyBytes, n, keyInuptSize - n);
                    break;
                }

                Buffer.BlockCopy(Ki, 0, keyBytes, n, blocksize);

                n += blocksize;
            }
            while (n < keyInuptSize);

            return keyBytes;
        }

        public static byte[] NFold(byte[] inBytes, int size)
        {
            var inBytesNum = inBytes.Length;
            var outBytesNum = size;

            var a = outBytesNum;
            var b = inBytesNum;
            var c = 0;

            while (b != 0)
            {
                c = b;
                b = a % b;
                a = c;
            }

            var lcm = (outBytesNum * inBytesNum) / a;

            var outBytes = new byte[outBytesNum];

            KerberosHash.Fill(outBytes, (byte)0);

            var tmpByte = 0;

            for (var i = lcm - 1; i >= 0; i--)
            {
                var tmp = ((inBytesNum << 3) - 1);
                tmp += (((inBytesNum << 3) + 13) * (i / inBytesNum));
                tmp += ((inBytesNum - (i % inBytesNum)) << 3);

                var msbit = tmp % (inBytesNum << 3);

                tmp = ((((inBytes[((inBytesNum - 1) - (msbit >> 3)) % inBytesNum] & 0xff) << 8) |
                    (inBytes[((inBytesNum) - (msbit >> 3)) % inBytesNum] & 0xff))
                    >> ((msbit & 7) + 1)) & 0xff;

                tmpByte += tmp;
                tmp = outBytes[i % outBytesNum] & 0xff;
                tmpByte += tmp;

                outBytes[i % outBytesNum] = (byte)(tmpByte & 0xff);

                tmpByte >>= 8;
            }

            if (tmpByte != 0)
            {
                for (var i = outBytesNum - 1; i >= 0; i--)
                {
                    tmpByte += (outBytes[i] & 0xff);
                    outBytes[i] = (byte)(tmpByte & 0xff);

                    tmpByte >>= 8;
                }
            }

            return outBytes;
        }
    }
}