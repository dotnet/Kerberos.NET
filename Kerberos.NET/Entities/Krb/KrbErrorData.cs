// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Security.Cryptography.Asn1;
using Kerberos.NET.Ndr;
using Kerberos.NET.Win32;

namespace Kerberos.NET.Entities
{
    public partial class KrbErrorData
    {
        public static bool CanDecode(ReadOnlyMemory<byte> encoded)
        {
            var reader = new AsnReader(encoded, AsnEncodingRules.DER);

            var tag = reader.ReadTagAndLength(out _, out _);

            return tag.HasSameClassAndValue(Asn1Tag.Sequence);
        }

        public KrbExtError DecodeExtendedError()
        {
            if (this.Type != KrbErrorDataType.KERB_ERR_TYPE_EXTENDED)
            {
                return null;
            }

            using (var buffer = new NdrBuffer(this.Value, align: false))
            {
                return new KrbExtError
                {
                    Status = (Win32StatusCode)buffer.ReadInt32LittleEndian(),
                    Reserved = buffer.ReadInt32LittleEndian(),
                    Flags = (ExtendedErrorFlag)buffer.ReadInt32LittleEndian()
                };
            }
        }
    }
}
