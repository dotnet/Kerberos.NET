using Kerberos.NET.Entities;

#pragma warning disable S101 // Types should be named in camel case

namespace Kerberos.NET.Crypto.AES
{
    public class AES256DecryptedData : AESDecryptedData
    {
        public AES256DecryptedData(KrbApReq token)
            : base(token)
        {
            Transformer = new AES256Transformer();
        }

        protected override KerberosCryptoTransformer Transformer { get; }
    }
}
