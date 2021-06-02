// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using Kerberos.NET.Entities.Pac;
using Kerberos.NET.Ndr;

namespace Kerberos.NET.Entities
{
    public class PacClientInfo : PacObject
    {
        public RpcFileTime ClientId { get; set; }

        [KerberosIgnore]
        public short NameLength { get; private set; }

        public string Name { get; set; }

        public override PacType PacType => PacType.CLIENT_NAME_TICKET_INFO;

        public override ReadOnlyMemory<byte> Marshal()
        {
            using (var buffer = new NdrBuffer())
            {
                this.NameLength = (short)(this.Name.Length * sizeof(char));

                buffer.WriteStruct(this.ClientId);
                buffer.WriteInt16LittleEndian(this.NameLength);

                if (this.NameLength > 0)
                {
                    buffer.WriteFixedPrimitiveArray(this.Name.AsSpan());
                }

                return buffer.ToMemory();
            }
        }

        public override void Unmarshal(ReadOnlyMemory<byte> bytes)
        {
            using (var buffer = new NdrBuffer(bytes))
            {
                this.ClientId = buffer.ReadStruct<RpcFileTime>();

                this.NameLength = buffer.ReadInt16LittleEndian();

                if (this.NameLength > 0)
                {
                    this.Name = buffer.ReadFixedPrimitiveArray<char>(this.NameLength / sizeof(char)).ToString();
                }
            }
        }
    }
}
