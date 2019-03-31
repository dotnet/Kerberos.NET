using Kerberos.NET.Crypto.AES;

#pragma warning disable S101 // Types should be named in camel case

namespace Kerberos.NET.Crypto
{
    internal class AES128Transformer : AESTransformer
    {
        private static readonly AESEncryptor encryptor = new AES128Encryptor();

        public AES128Transformer()
            : base(encryptor, new SHA1Hasher())
        {
        }
    }

    internal class AES128Encryptor : AESEncryptor
    {
        public AES128Encryptor()
            : base(16, 16, 16)
        { }
    }
}
