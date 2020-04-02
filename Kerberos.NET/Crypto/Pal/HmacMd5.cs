using System;
using System.Security.Cryptography;

namespace Kerberos.NET.Crypto
{
#if WEAKCRYPTO
    internal class HmacMd5 : IHmacAlgorithm
    {
        public ReadOnlyMemory<byte> ComputeHash(ReadOnlyMemory<byte> key, ReadOnlyMemory<byte> data)
        {
            byte[] keyArray = key.TryGetArrayFast();

            using var hmac = new HMACMD5(keyArray);
            ArraySegment<byte> dataArray = data.GetArraySegment();

            return hmac.ComputeHash(dataArray.Array, dataArray.Offset, dataArray.Count);
        }
    }
#endif
}
