// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;

namespace Kerberos.NET.Crypto
{
    public class HmacAes256KerberosChecksum : AesKerberosChecksum
    {
        public HmacAes256KerberosChecksum(ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> data)
            : base(CryptoService.CreateTransform(EncryptionType.AES256_CTS_HMAC_SHA1_96), signature, data)
        {
        }
    }
}