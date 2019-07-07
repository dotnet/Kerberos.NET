using System.Security;

namespace Kerberos.NET.Crypto
{
    public abstract class PacValidator
    {
        protected byte[] Signature { get; }

        protected byte[] Pac { get; }

        protected PacValidator(byte[] signature, byte[] pac)
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

        protected abstract bool ValidateInternal(KerberosKey key);
    }

    public class HmacAes256PacValidator : AesPacValidator
    {
        public HmacAes256PacValidator(byte[] signature, byte[] pac)
            : base(CryptographyService.CreateTransform(EncryptionType.AES256_CTS_HMAC_SHA1_96), signature, pac)
        {
        }
    }

    public class HmacAes128PacValidator : AesPacValidator
    {
        public HmacAes128PacValidator(byte[] signature, byte[] pac)
            : base(CryptographyService.CreateTransform(EncryptionType.AES128_CTS_HMAC_SHA1_96), signature, pac)
        {
        }
    }

    public abstract class AesPacValidator : PacValidator
    {
        private readonly KerberosCryptoTransformer decryptor;

        protected AesPacValidator(KerberosCryptoTransformer decryptor, byte[] signature, byte[] pac)
            : base(signature, pac)
        {
            this.decryptor = decryptor;
        }

        protected override bool ValidateInternal(KerberosKey key)
        {
            var actualChecksum = decryptor.MakeChecksum(
                key.GetKey(decryptor),
                KeyUsage.KU_PA_FOR_USER_ENC_CKSUM,
                KeyDerivationMode.Kc,
                Pac,
                decryptor.ChecksumSize
            );

            return KerberosCryptoTransformer.AreEqualSlow(actualChecksum, Signature);
        }
    }

    public class HmacMd5PacValidator : PacValidator
    {
        public HmacMd5PacValidator(byte[] signature, byte[] pac)
            : base(signature, pac)
        {
        }

        protected override bool ValidateInternal(KerberosKey key)
        {
            var crypto = CryptographyService.CreateTransform(EncryptionType.RC4_HMAC_NT);

            var actualChecksum = crypto.MakeChecksum(
                key.GetKey(crypto),
                Pac,
                KeyUsage.KU_PA_FOR_USER_ENC_CKSUM
            );

            return KerberosCryptoTransformer.AreEqualSlow(actualChecksum, Signature);
        }
    }
}
