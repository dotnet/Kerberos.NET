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
            : base(new AES256Decryptor(), new AES256Encryptor(), signature, ref pac)
        {
        }
    }

    public class HmacAes128PacValidator : AesPacValidator
    {
        public HmacAes128PacValidator(byte[] signature, ref byte[] pac)
            : base(new AES128Decryptor(), new AES128Encryptor(), signature, ref pac)
        {
        }
    }

    public abstract class AesPacValidator : PacValidator
    {
        private readonly AESDecryptor decryptor;
        private readonly AESEncryptor encryptor;

        protected AesPacValidator(AESDecryptor decryptor, AESEncryptor encryptor, byte[] signature, ref byte[] pac)
            : base(signature, ref pac)
        {
            this.decryptor = decryptor;
            this.encryptor = encryptor;
        }

        protected override bool ValidateInternal(KerberosKey key)
        {
            var constant = new byte[5];

            KerberosHash.ConvertToBigEndian((int)KeyUsage.KU_PA_FOR_USER_ENC_CKSUM, constant, 0);

            constant[4] = 0x99;

            var Ki = encryptor.DK(key.GetKey(encryptor), constant);

            var actualChecksum = decryptor.MakeChecksum(Ki, Pac, decryptor.ChecksumSize);

            return KerberosHash.AreEqualSlow(actualChecksum, Signature);
        }
    }

    public class HmacMd5PacValidator : PacValidator
    {
        public HmacMd5PacValidator(byte[] signature, ref byte[] pac)
            : base(signature, ref pac)
        {
        }

        protected override bool ValidateInternal(KerberosKey key)
        {
            var actualChecksum = KerberosHash.KerbChecksumHmacMd5(
               key.GetKey(new MD4Encryptor()),
               (int)KeyUsage.KU_PA_FOR_USER_ENC_CKSUM,
               Pac
           );

            return KerberosHash.AreEqualSlow(actualChecksum, Signature);
        }
    }
}
