using Kerberos.NET.Crypto.AES;

#pragma warning disable S101 // Types should be named in camel case

namespace Kerberos.NET.Crypto
{
    internal class AES256Transformer : AESTransformer
    {
        private const int Size = 32;

        public AES256Transformer()
            : base(Size)
        {
        }
    }
}
