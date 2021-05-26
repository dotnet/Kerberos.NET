// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Security;

namespace Kerberos.NET.Crypto
{
    public abstract class KerberosChecksum
    {
        public abstract int ChecksumSize { get; }

        public KeyUsage Usage { get; set; } = KeyUsage.PaForUserChecksum;

        public ReadOnlyMemory<byte> Signature { get; private set; }

        protected ReadOnlyMemory<byte> Data { get; private set; }

        protected KerberosChecksum(ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> data)
        {
            this.Signature = signature;
            this.Data = data;
        }

        public void Validate(KerberosKey key)
        {
            if (!this.ValidateInternal(key))
            {
                throw new SecurityException("Invalid checksum");
            }
        }

        public void Sign(KerberosKey key)
        {
            this.Signature = this.SignInternal(key);
        }

        protected abstract ReadOnlyMemory<byte> SignInternal(KerberosKey key);

        protected abstract bool ValidateInternal(KerberosKey key);
    }
}
