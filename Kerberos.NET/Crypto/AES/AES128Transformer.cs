using Kerberos.NET.Crypto.AES;

#pragma warning disable S101 // Types should be named in camel case

namespace Kerberos.NET.Crypto
{
    internal class AES128Transformer : AESTransformer
    {
        private const int Size = 16;

        public AES128Transformer()
            : base(Size)
        {
        }
    }
}
