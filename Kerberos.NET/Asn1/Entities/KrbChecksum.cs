
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using System;

namespace Kerberos.NET.Asn1.Entities
{
    public partial struct KrbChecksum
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
