using System;
using System.Security;

namespace Kerberos.NET.Crypto
{
    public abstract class KerberosChecksum
    {
        public ReadOnlyMemory<byte> Signature { get; private set; }

        protected ReadOnlyMemory<byte> Pac { get; private set; }

        protected KerberosChecksum(ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> pac)
        {
            Signature = signature;
            Pac = pac;
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
            Signature = SignInternal(key).AsMemory();
        }

        protected abstract ReadOnlySpan<byte> SignInternal(KerberosKey key);

        protected abstract bool ValidateInternal(KerberosKey key);
    }

    public class HmacAes256PacSign : AesPacKerberosChecksum
    {
        public HmacAes256PacSign(ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> pac)
            : base(CryptoService.CreateTransform(EncryptionType.AES256_CTS_HMAC_SHA1_96), signature, pac)
        {
        }
    }

    public class HmacAes128KerberosChecksum : AesPacKerberosChecksum
    {
        public HmacAes128KerberosChecksum(ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> pac)
            : base(CryptoService.CreateTransform(EncryptionType.AES128_CTS_HMAC_SHA1_96), signature, pac)
        {
        }
    }

    public abstract class AesPacKerberosChecksum : KerberosChecksum
    {
        private readonly KerberosCryptoTransformer decryptor;

        protected AesPacKerberosChecksum(KerberosCryptoTransformer decryptor, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> pac)
            : base(signature, pac)
        {
            this.decryptor = decryptor;
        }

        protected override ReadOnlySpan<byte> SignInternal(KerberosKey key)
        {
            return decryptor.MakeChecksum(
                Pac.Span,
                key,
                KeyUsage.PaForUserChecksum,
                KeyDerivationMode.Kc,
                decryptor.ChecksumSize
            );
        }

        protected override bool ValidateInternal(KerberosKey key)
        {
            var actualChecksum = SignInternal(key);

            return KerberosCryptoTransformer.AreEqualSlow(actualChecksum, Signature.Span);
        }
    }

    public class HmacMd5KerberosChecksum : KerberosChecksum
    {
        public HmacMd5KerberosChecksum(ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> pac)
            : base(signature, pac)
        {
        }

        protected override ReadOnlySpan<byte> SignInternal(KerberosKey key)
        {
            var crypto = CryptoService.CreateTransform(EncryptionType.RC4_HMAC_NT);

            return crypto.MakeChecksum(
                key.GetKey(crypto),
                Pac.Span,
                KeyUsage.PaForUserChecksum
            );
        }

        protected override bool ValidateInternal(KerberosKey key)
        {
            var actualChecksum = SignInternal(key);

            return KerberosCryptoTransformer.AreEqualSlow(actualChecksum, Signature.Span);
        }
    }
}
