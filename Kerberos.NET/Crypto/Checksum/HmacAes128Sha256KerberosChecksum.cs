// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;

namespace Kerberos.NET.Crypto
{
    public class HmacAes128Sha256KerberosChecksum : AesKerberosChecksum
    {
        public HmacAes128Sha256KerberosChecksum(ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> data)
            : base(CryptoService.CreateTransform(EncryptionType.AES128_CTS_HMAC_SHA256_128), signature, data)
        {
        }
    }
}
