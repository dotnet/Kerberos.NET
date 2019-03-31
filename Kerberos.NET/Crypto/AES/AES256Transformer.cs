using Kerberos.NET.Crypto.AES;

#pragma warning disable S101 // Types should be named in camel case

namespace Kerberos.NET.Crypto
{
    internal class AES256Transformer : AESTransformer
    {
        private static readonly AESEncryptor encryptor = new AES256Encryptor();

        public AES256Transformer()
            : base(encryptor, new SHA1Hasher())
        {
        }
    }

    internal class AES256Encryptor : AESEncryptor
    {
        public AES256Encryptor()
            : base(16, 32, 32)
        { }
    }
}
