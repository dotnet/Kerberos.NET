using System;
using System.Security.Cryptography;

namespace Kerberos.NET.Crypto
{
    internal class Md5 : IHashAlgorithm
    {
        public ReadOnlyMemory<byte> ComputeHash(ReadOnlySpan<byte> data)
        {
            var dataArray = data.ToArray();

            using (var md5 = MD5.Create())
            {
                return md5.ComputeHash(dataArray);
            }
        }

        public void Dispose() { }
    }
}
