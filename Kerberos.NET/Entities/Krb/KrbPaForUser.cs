using Kerberos.NET.Crypto;
using System;

namespace Kerberos.NET.Entities
{
    public partial class KrbPaForUser
    {
        private const ChecksumType PaForUserChecksumType = ChecksumType.KERB_CHECKSUM_HMAC_MD5;

        public void GenerateChecksum(KerberosKey key)
        {
            var dataLength = 0;

            dataLength += 4;

            foreach (var name in UserName.Name)
            {
                dataLength += name.Length;
            }

            dataLength += UserRealm.Length;
            dataLength += AuthPackage.Length;

            var checksumData = new Memory<byte>(new byte[dataLength]);

            Endian.ConvertToLittleEndian((int)UserName.Type, checksumData);

            var position = 4;

            for (var i = 0; i < UserName.Name.Length; i++)
            {
                Concat(checksumData, ref position, ref UserName.Name[i]);
            }

            Concat(checksumData, ref position, ref UserRealm);
            Concat(checksumData, ref position, ref AuthPackage);

            Checksum = KrbChecksum.Create(checksumData, key, KeyUsage.PaForUserChecksum, PaForUserChecksumType);
        }

        private static void Concat(Memory<byte> checksumData, ref int position, ref string value)
        {
            KerberosConstants.UnicodeStringToUtf8(value).CopyTo(checksumData.Span.Slice(position, value.Length));

            position += value.Length;
        }
    }
}
