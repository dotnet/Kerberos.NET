using Kerberos.NET.Crypto;
using System;
using System.Security;

namespace Kerberos.NET.Entities
{
    public partial class KrbPaForUser
    {
        private const ChecksumType PaForUserChecksumType = ChecksumType.KERB_CHECKSUM_HMAC_MD5;

        public void GenerateChecksum(KerberosKey key)
        {
            Checksum = GenerateChecksum(key, UserName, UserRealm, AuthPackage);
        }

        private static KrbChecksum GenerateChecksum(KerberosKey key, KrbPrincipalName userName, string userRealm, string authPackage)
        {
            var dataLength = 0;

            dataLength += 4;

            foreach (var name in userName.Name)
            {
                dataLength += name.Length;
            }

            dataLength += userRealm.Length;
            dataLength += authPackage.Length;

            var checksumData = new Memory<byte>(new byte[dataLength]);

            Endian.ConvertToLittleEndian((int)userName.Type, checksumData);

            var position = 4;

            for (var i = 0; i < userName.Name.Length; i++)
            {
                Concat(checksumData, ref position, ref userName.Name[i]);
            }

            Concat(checksumData, ref position, ref userRealm);
            Concat(checksumData, ref position, ref authPackage);

            return KrbChecksum.Create(checksumData, key, KeyUsage.PaForUserChecksum, PaForUserChecksumType);
        }

        public void ValidateChecksum(KerberosKey key)
        {
            var expected = GenerateChecksum(key, UserName, UserRealm, AuthPackage);

            if (!KerberosCryptoTransformer.AreEqualSlow(expected.Checksum.Span, this.Checksum.Checksum.Span))
            {
                throw new SecurityException("Invalid checksum");
            }
        }

        private static void Concat(Memory<byte> checksumData, ref int position, ref string value)
        {
            KerberosConstants.UnicodeStringToUtf8(value).CopyTo(checksumData.Span.Slice(position, value.Length));

            position += value.Length;
        }
    }
}
