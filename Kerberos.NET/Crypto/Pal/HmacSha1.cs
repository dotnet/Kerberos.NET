using System;
using System.Security.Cryptography;
using static Kerberos.NET.BinaryExtensions;

namespace Kerberos.NET.Crypto
{
    internal class HmacSha1 : IHmacAlgorithm
    {
        public ReadOnlyMemory<byte> ComputeHash(
            ReadOnlyMemory<byte> key,
            ReadOnlyMemory<byte> data
        )
        {
            var keyArray = TryGetArrayFast(key);
            var dataArray = TryGetArrayFast(data);

            using (var hmac = new HMACSHA1(keyArray))
            {
                return hmac.ComputeHash(dataArray, 0, data.Length);
            }
        }
    }
}
