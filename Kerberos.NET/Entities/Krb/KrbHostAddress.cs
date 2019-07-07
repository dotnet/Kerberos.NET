using System.Text;

namespace Kerberos.NET.Entities
{
    public partial class KrbHostAddress
    {
        public string DecodeAddress()
        {
            switch (this.AddressType)
            {
                case AddressType.NetBios:
                    return Encoding.ASCII.GetString(this.Address.ToArray());
            }

            return null;
        }
    }
}
