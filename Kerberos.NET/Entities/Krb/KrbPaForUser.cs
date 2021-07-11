// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Buffers.Binary;
using System.Security;
using Kerberos.NET.Crypto;
using static Kerberos.NET.Entities.KerberosConstants;

namespace Kerberos.NET.Entities
{
    public partial class KrbPaForUser
    {
        private const ChecksumType PaForUserChecksumType = ChecksumType.KERB_CHECKSUM_HMAC_MD5;

        public void GenerateChecksum(KerberosKey key)
        {
            this.Checksum = GenerateChecksum(key, this.UserName, this.UserRealm, this.AuthPackage);
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

            BinaryPrimitives.WriteInt32LittleEndian(checksumData.Span, (int)userName.Type);

            var position = 4;

            for (var i = 0; i < userName.Name.Length; i++)
            {
                Concat(checksumData, userName.Name[i], ref position);
            }

            Concat(checksumData, userRealm, ref position);
            Concat(checksumData, authPackage, ref position);

            return KrbChecksum.Create(checksumData, key, KeyUsage.PaForUserChecksum, PaForUserChecksumType);
        }

        public void ValidateChecksum(KerberosKey key)
        {
            var expected = GenerateChecksum(key, this.UserName, this.UserRealm, this.AuthPackage);

            if (!KerberosCryptoTransformer.AreEqualSlow(expected.Checksum.Span, this.Checksum.Checksum.Span))
            {
                throw new SecurityException("Invalid checksum");
            }
        }

        private static void Concat(Memory<byte> checksumData, string value, ref int position)
        {
            UnicodeStringToUtf8(value).CopyTo(checksumData.Slice(position, value.Length));

            position += value.Length;
        }
    }
}
