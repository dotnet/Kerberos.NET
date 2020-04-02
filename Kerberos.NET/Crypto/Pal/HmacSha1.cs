using System;
using System.Security.Cryptography;

namespace Kerberos.NET.Crypto
{
    internal class HmacSha1 : IHmacAlgorithm
    {
        public ReadOnlyMemory<byte> ComputeHash(ReadOnlyMemory<byte> key, ReadOnlyMemory<byte> data)
        {
            byte[] keyArray = key.TryGetArrayFast();

            using var hmac = new HMACSHA1(keyArray);
            ArraySegment<byte> dataArray = data.GetArraySegment();

            return hmac.ComputeHash(dataArray.Array, dataArray.Offset, dataArray.Count);
        }
    }
}
