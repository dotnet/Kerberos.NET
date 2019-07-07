using Kerberos.NET.Crypto;
using System;

namespace Kerberos.NET.Entities.SpNego
{
    public class NegoExContextToken : ContextToken
    {
        public NegoExContextToken(ReadOnlyMemory<byte> data)
        {
            Token = new NegotiateExtension(data);
        }

        public NegotiateExtension Token { get; }

        public override DecryptedKrbApReq DecryptApReq(KeyTable keys)
        {
            throw new NotSupportedException("NegoEx is not supported");
        }
    }
}
