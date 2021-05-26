using System;
using Kerberos.NET.Crypto;

namespace KerbDump
{
    public class NoopTransform : KerberosCryptoTransformer
    {
        public override int ChecksumSize => throw new NotImplementedException();

        public override int BlockSize => throw new NotImplementedException();

        public override int KeySize => throw new NotImplementedException();

        public override ChecksumType ChecksumType => ChecksumType.HMAC_SHA1_96_AES128;

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
}
