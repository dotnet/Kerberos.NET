// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities.Pac;
using Kerberos.NET.Ndr;

namespace Kerberos.NET.Entities
{
    public class PacCredentialInfo : PacObject
    {
        public int Version { get; set; }

        public EncryptionType EncryptionType { get; set; }

        public ReadOnlyMemory<byte> SerializedData { get; set; }

        public override PacType PacType => PacType.CREDENTIAL_TYPE;

        public override ReadOnlyMemory<byte> Marshal()
        {
            using (var buffer = new NdrBuffer())
            {
                buffer.WriteInt32LittleEndian(this.Version);
                buffer.WriteInt32LittleEndian((int)this.EncryptionType);
                buffer.WriteSpan(this.SerializedData.Span);

                return buffer.ToMemory(alignment: 8);
            }
        }

        public override void Unmarshal(ReadOnlyMemory<byte> bytes)
        {
            using (var stream = new NdrBuffer(bytes))
            {
                this.Version = stream.ReadInt32LittleEndian();

                this.EncryptionType = (EncryptionType)stream.ReadInt32LittleEndian();

                this.SerializedData = stream.ReadMemory(stream.BytesAvailable);
            }
        }
    }
}
