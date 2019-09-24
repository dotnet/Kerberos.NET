using Kerberos.NET.Crypto;
using System;

namespace Kerberos.NET.Entities
{
    public partial class KrbChecksum
    {
        internal const ChecksumType ChecksumContainsDelegationType = (ChecksumType)0x8003;

        public DelegationInfo DecodeDelegation()
        {
            if (Type != ChecksumContainsDelegationType)
            {
                throw new InvalidOperationException($"Cannot decode delegation ticket in checksum because type is {Type}");
            }

            return new DelegationInfo().Decode(this.Checksum);
        }

        public static KrbChecksum EncodeDelegationChecksum(DelegationInfo deleg)
        {
            return new KrbChecksum
            {
                Type = ChecksumContainsDelegationType,
                Checksum = deleg.Encode()
            };
        }

        public static KrbChecksum Create(ReadOnlyMemory<byte> data, KerberosKey key, KeyUsage ku, ChecksumType type = 0)
        {
            if (type == 0)
            {
                type = CryptoService.ConvertType(key.EncryptionType);
            }

            var checksum = CryptoService.CreateChecksum(type, signatureData: data);

            checksum.Usage = ku;

            checksum.Sign(key);

            return new KrbChecksum
            {
                Checksum = checksum.Signature,
                Type = type
            };
        }
    }
}
