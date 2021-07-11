// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Security.Cryptography;
using System.Text;

namespace Kerberos.NET.Crypto
{
    public class AES256Sha384Transformer : Rfc8009Transformer
    {
        private const int Aes256KeySize = Aes256Sha384KeyLength / 8;
        private static readonly ReadOnlyMemory<byte> EncTypeName = Encoding.UTF8.GetBytes("aes256-cts-hmac-sha384-192");

        public AES256Sha384Transformer()
            : base(Aes256KeySize, EncTypeName)
        {
        }

        protected override HashAlgorithmName Pbkdf2Hash => HashAlgorithmName.SHA384;

        public override int ChecksumSize => Aes256Sha384ChecksumLength / 8;

        public override ChecksumType ChecksumType => ChecksumType.HMAC_SHA384_192_AES256;

        public override EncryptionType EncryptionType => EncryptionType.AES256_CTS_HMAC_SHA384_192;

        protected override ReadOnlyMemory<byte> Hmac(ReadOnlyMemory<byte> key, ReadOnlyMemory<byte> data)
        {
            var hmac = CryptoPal.Platform.HmacSha384(key);

            return hmac.ComputeHash(data);
        }
    }
}
