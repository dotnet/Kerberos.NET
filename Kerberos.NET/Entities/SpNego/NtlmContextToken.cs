using Kerberos.NET.Crypto;
using System;

namespace Kerberos.NET.Entities.SpNego
{
    public class NtlmContextToken : ContextToken
    {
        public NtlmContextToken(byte[] data)
        {
            Token = new NtlmMessage(data);
        }

        public NtlmMessage Token { get; }

        public override DecryptedKrbApReq DecryptApReq(KeyTable keys)
        {
            throw new NotSupportedException("NTLM is not supported");
        }
    }
}
