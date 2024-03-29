﻿using System;
using Kerberos.NET.Crypto;

namespace KerbDump
{
    public class NoopTransform : KerberosCryptoTransformer
    {
        public override int ChecksumSize => throw new NotImplementedException();

        public override int BlockSize => throw new NotImplementedException();

        public override int KeySize => throw new NotImplementedException();

        public override ChecksumType ChecksumType => ChecksumType.HMAC_SHA1_96_AES128;

        public override EncryptionType EncryptionType => EncryptionType.NULL;

        public override ReadOnlyMemory<byte> Encrypt(ReadOnlyMemory<byte> data, KerberosKey key, KeyUsage usage)
        {
            return data;
        }

        public override ReadOnlyMemory<byte> Decrypt(ReadOnlyMemory<byte> cipher, KerberosKey key, KeyUsage usage)
        {
            return cipher.ToArray();
        }

        public override ReadOnlyMemory<byte> String2Key(KerberosKey key)
        {
            return key.PasswordBytes;
        }
    }

    public class NoopChecksum : KerberosChecksum
    {
        public NoopChecksum(ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> data) : base(signature, data)
        {
        }

        public override int ChecksumSize { get; }

        protected override ReadOnlyMemory<byte> SignInternal(KerberosKey key)
        {
            return Array.Empty<byte>();
        }

        protected override bool ValidateInternal(KerberosKey key)
        {
            return true;
        }
    }
}
