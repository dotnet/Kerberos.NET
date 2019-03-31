#pragma warning disable S101 // Types should be named in camel case

using System.Security.Cryptography;

namespace Kerberos.NET.Crypto.AES
{
    public class SHA1Hasher : IHasher
    {
        public byte[] Hmac(byte[] key, byte[] data)
        {
            using (var hmac = new HMACSHA1(key))
            {
                return hmac.ComputeHash(data);
            }
        }
    }
}
