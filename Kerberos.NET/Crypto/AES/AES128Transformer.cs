// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

#pragma warning disable S101 // Types should be named in camel case

namespace Kerberos.NET.Crypto
{
    internal class AES128Transformer : AESTransformer
    {
        private const int Size = 16;

        public AES128Transformer()
            : base(Size)
        {
        }

        public override ChecksumType ChecksumType => ChecksumType.HMAC_SHA1_96_AES128;
    }
}