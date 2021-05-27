// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;

namespace Kerberos.NET.Crypto
{
    public abstract class AesKerberosChecksum : KerberosChecksum
    {
        private readonly KerberosCryptoTransformer decryptor;

        protected AesKerberosChecksum(KerberosCryptoTransformer decryptor, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> data)
            : base(signature, data)
        {
            this.decryptor = decryptor;
        }

        public override int ChecksumSize => 12; // bytes

        protected override ReadOnlyMemory<byte> SignInternal(KerberosKey key)
        {
            return this.decryptor.MakeChecksum(
                this.Data,
                key,
                this.Usage,
                KeyDerivationMode.Kc,
                this.decryptor.ChecksumSize
            );
        }

        protected override bool ValidateInternal(KerberosKey key)
        {
            var actualChecksum = this.SignInternal(key);

            return KerberosCryptoTransformer.AreEqualSlow(actualChecksum.Span, this.Signature.Span);
        }
    }
}