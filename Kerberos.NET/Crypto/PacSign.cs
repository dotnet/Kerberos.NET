using System;
using System.Security;

namespace Kerberos.NET.Crypto
{
    public abstract class PacSign
    {
        public ReadOnlyMemory<byte> Signature { get; private set; }

        protected ReadOnlyMemory<byte> Pac { get; private set; }

        protected PacSign(byte[] signature = null, byte[] pac = null)
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
            Signature = SignInternal(key);
        }

        protected abstract ReadOnlyMemory<byte> SignInternal(KerberosKey key);

        protected abstract bool ValidateInternal(KerberosKey key);
    }

    public class HmacAes256PacSign : AesPacSign
    {
        public HmacAes256PacSign(byte[] signature = null, byte[] pac = null)
            : base(CryptographyService.CreateTransform(EncryptionType.AES256_CTS_HMAC_SHA1_96), signature, pac)
        {
        }
    }

    public class HmacAes128PacSign : AesPacSign
    {
        public HmacAes128PacSign(byte[] signature = null, byte[] pac = null)
            : base(CryptographyService.CreateTransform(EncryptionType.AES128_CTS_HMAC_SHA1_96), signature, pac)
        {
        }
    }

    public abstract class AesPacSign : PacSign
    {
        private readonly KerberosCryptoTransformer decryptor;

        protected AesPacSign(KerberosCryptoTransformer decryptor, byte[] signature, byte[] pac)
            : base(signature, pac)
        {
            this.decryptor = decryptor;
        }

        protected override ReadOnlyMemory<byte> SignInternal(KerberosKey key)
        {
            return decryptor.MakeChecksum(
                Pac.ToArray(),
                key.GetKey(decryptor),
                KeyUsage.PaForUserChecksum,
                KeyDerivationMode.Kc,
                decryptor.ChecksumSize
            );
        }

        protected override bool ValidateInternal(KerberosKey key)
        {
            var actualChecksum = SignInternal(key);

            return KerberosCryptoTransformer.AreEqualSlow(actualChecksum.ToArray(), Signature.ToArray());
        }
    }

    public class HmacMd5PacSign : PacSign
    {
        public HmacMd5PacSign(byte[] signature = null, byte[] pac = null)
            : base(signature, pac)
        {
        }

        protected override ReadOnlyMemory<byte> SignInternal(KerberosKey key)
        {
            var crypto = CryptographyService.CreateTransform(EncryptionType.RC4_HMAC_NT);

            return crypto.MakeChecksum(
                key.GetKey(crypto),
                Pac.ToArray(),
                KeyUsage.PaForUserChecksum
            );
        }

        protected override bool ValidateInternal(KerberosKey key)
        {
            var actualChecksum = SignInternal(key);

            return KerberosCryptoTransformer.AreEqualSlow(actualChecksum.ToArray(), Signature.ToArray());
        }
    }
}
