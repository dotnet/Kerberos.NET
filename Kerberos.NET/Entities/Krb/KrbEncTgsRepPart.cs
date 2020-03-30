using Kerberos.NET.Crypto;

namespace Kerberos.NET.Entities
{
    public partial class KrbEncTgsRepPart
    {
        public override KeyUsage KeyUsage => KeyUsage.EncTgsRepPartSubSessionKey;
    }
}
