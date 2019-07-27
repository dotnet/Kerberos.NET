using System;
using System.Security;

namespace Kerberos.NET.Crypto
{
    public abstract class KerberosChecksum
    {
        public ReadOnlyMemory<byte> Signature { get; private set; }

        protected ReadOnlyMemory<byte> Pac { get; private set; }

        protected KerberosChecksum(byte[] signature = null, byte[] pac = null)
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

    public class HmacAes256PacSign : AesPacKerberosChecksum
    {
        public HmacAes256PacSign(byte[] signature = null, byte[] pac = null)
            : base(CryptoService.CreateTransform(EncryptionType.AES256_CTS_HMAC_SHA1_96), signature, pac)
        {
        }
    }

    public class HmacAes128KerberosChecksum : AesPacKerberosChecksum
    {
        public HmacAes128KerberosChecksum(byte[] signature = null, byte[] pac = null)
            : base(CryptoService.CreateTransform(EncryptionType.AES128_CTS_HMAC_SHA1_96), signature, pac)
        {
        }
    }

    public abstract class AesPacKerberosChecksum : KerberosChecksum
    {
        private readonly KerberosCryptoTransformer decryptor;

        protected AesPacKerberosChecksum(KerberosCryptoTransformer decryptor, byte[] signature, byte[] pac)
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

    public class HmacMd5KerberosChecksum : KerberosChecksum
    {
        public HmacMd5KerberosChecksum(byte[] signature = null, byte[] pac = null)
            : base(signature, pac)
        {
        }

        protected override ReadOnlyMemory<byte> SignInternal(KerberosKey key)
        {
            var crypto = CryptoService.CreateTransform(EncryptionType.RC4_HMAC_NT);

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
