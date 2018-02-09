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

        public static byte[] MD4(byte[] key)
        {
            return new MD4().ComputeHash(key);
        }

        public static byte[] MD4(string password)
        {
            return MD4(Encoding.Unicode.GetBytes(password));
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
    }
}