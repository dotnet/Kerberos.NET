using System;
using System.Security;

namespace Kerberos.NET.Crypto
{
    public abstract class KerberosChecksum
    {
        public KeyUsage Usage { get; set; } = KeyUsage.PaForUserChecksum;

        public ReadOnlyMemory<byte> Signature { get; private set; }

        protected ReadOnlyMemory<byte> Data { get; private set; }

        protected KerberosChecksum(ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> data)
        {
            Signature = signature;
            Data = data;
        }

        public void Validate(KerberosKey key)
        {
            if (!ValidateInternal(key))
            {
                throw new SecurityException("Invalid checksum");
            }
        }

        public void Sign(KerberosKey key)
        {
            Signature = SignInternal(key);
        }

        protected abstract ReadOnlyMemory<byte> SignInternal(KerberosKey key);

        protected abstract bool ValidateInternal(KerberosKey key);
    }

    public class HmacAes256KerberosChecksum : AesKerberosChecksum
    {
        public HmacAes256KerberosChecksum(ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> data)
            : base(CryptoService.CreateTransform(EncryptionType.AES256_CTS_HMAC_SHA1_96), signature, data)
        {
        }
    }

    public class HmacAes128KerberosChecksum : AesKerberosChecksum
    {
        public HmacAes128KerberosChecksum(ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> data)
            : base(CryptoService.CreateTransform(EncryptionType.AES128_CTS_HMAC_SHA1_96), signature, data)
        {
        }
    }

    public abstract class AesKerberosChecksum : KerberosChecksum
    {
        private readonly KerberosCryptoTransformer decryptor;

        protected AesKerberosChecksum(KerberosCryptoTransformer decryptor, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> data)
            : base(signature, data)
        {
            this.decryptor = decryptor;
        }

        protected override ReadOnlyMemory<byte> SignInternal(KerberosKey key)
        {
            return decryptor.MakeChecksum(
                Data,
                key,
                Usage,
                KeyDerivationMode.Kc,
                decryptor.ChecksumSize
            );
        }

        protected override bool ValidateInternal(KerberosKey key)
        {
            var actualChecksum = SignInternal(key);

            return KerberosCryptoTransformer.AreEqualSlow(actualChecksum.Span, Signature.Span);
        }
    }
#if WEAKCRYPTO
    public class HmacMd5KerberosChecksum : KerberosChecksum
    {
        public HmacMd5KerberosChecksum(ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> data)
            : base(signature, data)
        {
        }

        protected override ReadOnlyMemory<byte> SignInternal(KerberosKey key)
        {
            var crypto = CryptoService.CreateTransform(EncryptionType.RC4_HMAC_NT);

            return crypto.MakeChecksum(
                key.GetKey(crypto),
                Data.Span,
                Usage
            );
        }

        protected override bool ValidateInternal(KerberosKey key)
        {
            var actualChecksum = SignInternal(key);

            return KerberosCryptoTransformer.AreEqualSlow(actualChecksum.Span, Signature.Span);
        }
    }
#endif
}
