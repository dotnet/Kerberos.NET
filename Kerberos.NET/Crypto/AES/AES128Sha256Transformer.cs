// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Security.Cryptography;
using System.Text;

namespace Kerberos.NET.Crypto
{
    public class AES128Sha256Transformer : Rfc8009Transformer
    {
        private const int Aes128KeySize = Aes128Sha256KeyLength / 8;
        private static readonly ReadOnlyMemory<byte> EncTypeName = Encoding.UTF8.GetBytes("aes128-cts-hmac-sha256-128");

        public AES128Sha256Transformer()
            : base(Aes128KeySize, EncTypeName)
        {
        }

        protected override HashAlgorithmName Pbkdf2Hash => HashAlgorithmName.SHA256;

        public override int ChecksumSize => Aes128KeySize;

        public override ChecksumType ChecksumType => ChecksumType.HMAC_SHA256_128_AES128;

        public override EncryptionType EType => EncryptionType.AES128_CTS_HMAC_SHA256_128;

        protected override ReadOnlyMemory<byte> Hmac(ReadOnlyMemory<byte> key, ReadOnlyMemory<byte> data)
        {
            var hmac = CryptoPal.Platform.HmacSha256(key);

            return hmac.ComputeHash(data);
        }
    }
}
