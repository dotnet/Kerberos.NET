// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Security.Cryptography;

namespace Kerberos.NET.Crypto
{
    public class AES256Sha384Transformer : Rfc8009Transformer
    {
        public AES256Sha384Transformer()
            : base(32, "aes256-cts-hmac-sha384-192")
        {
        }

        protected override HashAlgorithmName Pbkdf2Hash => HashAlgorithmName.SHA384;

        public override int ChecksumSize => 24;

        public override ChecksumType ChecksumType => ChecksumType.HMAC_SHA384_192_AES256;

        protected override ReadOnlyMemory<byte> Hmac(ReadOnlyMemory<byte> key, ReadOnlyMemory<byte> data)
        {
            var hmac = CryptoPal.Platform.HmacSha384(key);

            return hmac.ComputeHash(data);
        }
    }
}
