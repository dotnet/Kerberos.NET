using Kerberos.NET.Entities;

#pragma warning disable S101 // Types should be named in camel case

namespace Kerberos.NET.Crypto
{
    public abstract class AESDecryptedData : DecryptedData
    {
        protected AESDecryptedData(KrbApReq token, KerberosCryptoTransformer transformer)
            : base(token, transformer)
        {
        }
    }
}