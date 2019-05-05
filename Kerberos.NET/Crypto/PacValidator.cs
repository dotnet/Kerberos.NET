using Kerberos.NET.Crypto.AES;
using Kerberos.NET.Entities;
using System.Security;

namespace Kerberos.NET.Crypto
{
    public abstract class PacValidator
    {
        protected byte[] Signature { get; }

        protected byte[] Pac { get; }

        protected PacValidator(byte[] signature, ref byte[] pac)
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
        public HmacAes256PacValidator(byte[] signature, ref byte[] pac)
            : base(new AES256Transformer(), new AES256Encryptor(), signature, ref pac)
        {
        }
    }

    public class HmacAes128PacValidator : AesPacValidator
    {
        public HmacAes128PacValidator(byte[] signature, ref byte[] pac)
            : base(new AES128Transformer(), new AES128Encryptor(), signature, ref pac)
        {
        }
    }

    public abstract class AesPacValidator : PacValidator
    {
        private readonly AESTransformer decryptor;
        private readonly AESEncryptor encryptor;

        protected AesPacValidator(AESTransformer decryptor, AESEncryptor encryptor, byte[] signature, ref byte[] pac)
            : base(signature, ref pac)
        {
            this.decryptor = decryptor;
            this.encryptor = encryptor;
        }

        protected override bool ValidateInternal(KerberosKey key)
        {
            var constant = new byte[5];

            Endian.ConvertToBigEndian((int)KeyUsage.KU_PA_FOR_USER_ENC_CKSUM, constant, 0);

            constant[4] = 0x99;

            var Ki = encryptor.DK(key.GetKey(encryptor), constant);

            var actualChecksum = decryptor.MakeChecksum(Ki, Pac, decryptor.ChecksumSize);

            return KerberosCryptoTransformer.AreEqualSlow(actualChecksum, Signature);
        }
    }

    public class HmacMd5PacValidator : PacValidator
    {
        public HmacMd5PacValidator(byte[] signature, ref byte[] pac)
            : base(signature, ref pac)
        {
        }

        private readonly MD4Encryptor encryptor = new MD4Encryptor();

        protected override bool ValidateInternal(KerberosKey key)
        {
            var crypto = new RC4Transformer(encryptor);

            var actualChecksum = crypto.MakeChecksum(
                key.GetKey(encryptor), 
                Pac, 
                0, 
                (int)KeyUsage.KU_PA_FOR_USER_ENC_CKSUM
            );

            return KerberosCryptoTransformer.AreEqualSlow(actualChecksum, Signature);
        }
    }
}
