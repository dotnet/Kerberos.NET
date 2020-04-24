using System;
using System.Security.Cryptography.Asn1;
using Kerberos.NET.Crypto;

namespace Kerberos.NET.Entities
{
    public partial class KrbEncTgsRepPart
    {
        private static readonly Asn1Tag KrbEncTgsRepPartTag = new Asn1Tag(TagClass.Application, 26);

        public override KeyUsage KeyUsage => KeyUsage.EncTgsRepPartSubSessionKey;

        public static bool CanDecode(ReadOnlyMemory<byte> encoded)
        {
            return CanDecode(encoded, KrbEncTgsRepPartTag);
        }
    }
}
