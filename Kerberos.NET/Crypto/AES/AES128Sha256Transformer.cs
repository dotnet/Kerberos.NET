// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Security.Cryptography;

namespace Kerberos.NET.Crypto
{
    public class AES128Sha256Transformer : Rfc8009Transformer
    {
        public AES128Sha256Transformer()
            : base(16, "aes128-cts-hmac-sha256-128")
        {
        }

        protected override HashAlgorithmName Pbkdf2Hash => HashAlgorithmName.SHA256;

        public override int ChecksumSize => 16;

        public override ChecksumType ChecksumType => ChecksumType.HMAC_SHA256_128_AES128;

        protected override ReadOnlyMemory<byte> Hmac(ReadOnlyMemory<byte> key, ReadOnlyMemory<byte> data)
        {
            var hmac = CryptoPal.Platform.HmacSha256(key);

            return hmac.ComputeHash(data);
        }
    }
}
