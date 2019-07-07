
using Kerberos.NET.Crypto;
using System;

namespace Kerberos.NET.Entities
{
    public partial class KrbChecksum
    {
        private const int ChecksumContainsDelegationType = 0x8003;

        public DelegationInfo DecodeDelegation()
        {
            if (Type != (ChecksumType)ChecksumContainsDelegationType)
            {
                throw new InvalidOperationException($"Cannot decode delegation ticket in checksum because type is {Type}");
            }

            return new DelegationInfo().Decode(this.Checksum.ToArray());
        }
    }
}
