// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;

namespace Kerberos.NET.Crypto
{
#if WEAKCRYPTO
    public class HmacMd5KerberosChecksum : KerberosChecksum
    {
        public HmacMd5KerberosChecksum(ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> data)
            : base(signature, data)
        {
        }

        public override int ChecksumSize => 16; // bytes

        protected override ReadOnlyMemory<byte> SignInternal(KerberosKey key)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            var crypto = CryptoService.CreateTransform(EncryptionType.RC4_HMAC_NT);

            return crypto.MakeChecksum(
                key.GetKey(crypto),
                this.Data.Span,
                this.Usage
            );
        }

        protected override bool ValidateInternal(KerberosKey key)
        {
            var actualChecksum = this.SignInternal(key);

            return KerberosCryptoTransformer.AreEqualSlow(actualChecksum.Span, this.Signature.Span);
        }
    }
#endif
}