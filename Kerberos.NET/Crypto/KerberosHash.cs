using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

namespace Kerberos.NET.Crypto
{
    public static class KerberosHash
    {
        public static byte[] SHA256(string value)
        {
            return SHA256(Encoding.UTF8.GetBytes(value));
        }

        public static byte[] SHA256(byte[] bytes)
        {
            using (var sha = System.Security.Cryptography.SHA256.Create())
            {
                return sha.ComputeHash(bytes);
            }
        }

        public static byte[] HMACMD5(byte[] key, byte[] data)
        {
            using (HMACMD5 hmac = new HMACMD5(key))
            {
                return hmac.ComputeHash(data);
            }
        }

        public static byte[] KerbChecksumHmacMd5(byte[] key, int messageType, byte[] data)
        {
            var ksign = HMACMD5(key, Encoding.ASCII.GetBytes("signaturekey\0"));

            var tmp = MD5(ConvertToLittleEndian(messageType).Concat(data).ToArray());

            return HMACMD5(ksign, tmp);
        }

        public static void ConvertToBigEndian(int val, byte[] bytes, int offset)
        {
            bytes[offset + 0] = (byte)((val >> 24) & 0xff);
            bytes[offset + 1] = (byte)((val >> 16) & 0xff);
            bytes[offset + 2] = (byte)((val >> 8) & 0xff);
            bytes[offset + 3] = (byte)((val) & 0xff);
        }

        public static void ConvertToLittleEndian(int val, byte[] bytes, int offset)
        {
            bytes[offset + 0] = (byte)(val & 0xFF);
            bytes[offset + 1] = (byte)((val >> 8) & 0xFF);
            bytes[offset + 2] = (byte)((val >> 16) & 0xFF);
            bytes[offset + 3] = (byte)((val >> 24) & 0xFF);
        }

        private static byte[] ConvertToLittleEndian(int thing)
        {
            byte[] bytes = new byte[4];

            ConvertToLittleEndian(thing, bytes, 0);

            return bytes;
        }

        public static byte[] MD4(byte[] key)
        {
            return new MD4().ComputeHash(key);
        }

        public static byte[] MD5(byte[] data)
        {
            return System.Security.Cryptography.MD5.Create().ComputeHash(data);
        }

        public static byte[] KerberosHMAC(IHasher hashProvider, byte[] key, byte[] data)
        {
            return KerberosHMAC(hashProvider, key, data, 0, data.Length);
        }

        private static byte[] KerberosHMAC(IHasher hashProvider, byte[] key, byte[] data, int start, int len)
        {
            var blockSize = hashProvider.BlockSize;

            var innerPaddedKey = new byte[blockSize];
            var outerPaddedKey = new byte[blockSize];

            Fill(innerPaddedKey, (byte)0x36);

            for (int i = 0; i < key.Length; i++)
            {
                innerPaddedKey[i] ^= key[i];
            }

            Fill(outerPaddedKey, (byte)0x5c);

            for (int i = 0; i < key.Length; i++)
            {
                outerPaddedKey[i] ^= key[i];
            }

            hashProvider.Hash(innerPaddedKey);

            hashProvider.Hash(data, start, len);

            var tmp = hashProvider.CalculateDigest();

            hashProvider.Hash(outerPaddedKey);
            hashProvider.Hash(tmp);

            return hashProvider.CalculateDigest();
        }

        public static void Fill<T>(T[] array, T value)
        {
            for (var i = 0; i < array.Length; i++)
            {
                array[i] = value;
            }
        }

        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        public static bool AreEqualSlow(byte[] left, byte[] right, int rightLength = 0)
        {
            if (rightLength <= 0)
            {
                rightLength = right.Length;
            }

            var diff = left.Length ^ rightLength;

            for (var i = 0; i < left.Length; i++)
            {
                diff |= (left[i] ^ right[i]);
            }

            return diff == 0;
        }
    }
}