using Kerberos.NET.Crypto.AES;

#pragma warning disable S101 // Types should be named in camel case

namespace Kerberos.NET.Crypto
{
    internal class AES256Decryptor : AESDecryptor
    {
        private static readonly IEncryptor encryptor = new AES256Encryptor();

        public AES256Decryptor()
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
