// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Buffers.Binary;
using System.Runtime.InteropServices;
using Kerberos.NET.Entities.Pac;
using Kerberos.NET.Ndr;

#pragma warning disable S2344 // Enumeration type names should not have "Flags" or "Enum" suffixes

namespace Kerberos.NET.Entities
{
    [Flags]
    public enum UpnDomainFlags
    {
        U = 1
    }

    public class UpnDomainInfo : PacObject
    {
        public override ReadOnlySpan<byte> Marshal()
        {
            using (var buffer = new NdrBuffer())
            {
                var upnBytes = MemoryMarshal.Cast<char, byte>(this.Upn.AsSpan());
                var domainBytes = MemoryMarshal.Cast<char, byte>(this.Domain.AsSpan());

                buffer.WriteInt16LittleEndian((short)upnBytes.Length);
                buffer.WriteInt16LittleEndian(2 + 2 + 2 + 2 + 4 + 4); // + 4 to align on 8 boundary

                buffer.WriteInt16LittleEndian((short)domainBytes.Length);
                buffer.WriteInt16LittleEndian((short)(2 + 2 + 2 + 2 + 2 + 4 + 4 + upnBytes.Length));

                buffer.WriteInt32LittleEndian((int)this.Flags);

                buffer.WriteInt32LittleEndian(0);
                buffer.WriteFixedPrimitiveArray(upnBytes);

                buffer.WriteInt16LittleEndian(0);
                buffer.WriteFixedPrimitiveArray(domainBytes);

                return buffer.ToSpan(alignment: 8);
            }
        }

        public override void Unmarshal(ReadOnlyMemory<byte> bytes)
        {
            var span = bytes.Span;

            this.UpnLength = BinaryPrimitives.ReadInt16LittleEndian(span.Slice(0, 2));
            this.UpnOffset = BinaryPrimitives.ReadInt16LittleEndian(span.Slice(2, 2));

            this.DnsDomainNameLength = BinaryPrimitives.ReadInt16LittleEndian(span.Slice(4, 2));
            this.DnsDomainNameOffset = BinaryPrimitives.ReadInt16LittleEndian(span.Slice(6, 2));

            this.Flags = (UpnDomainFlags)BinaryPrimitives.ReadInt32LittleEndian(span.Slice(8, 4));

            this.Upn = MemoryMarshal.Cast<byte, char>(span.Slice(this.UpnOffset, this.UpnLength)).ToString();

            this.Domain = MemoryMarshal.Cast<byte, char>(span.Slice(this.DnsDomainNameOffset, this.DnsDomainNameLength)).ToString();
        }

        public string Upn { get; set; }

        public string Domain { get; set; }

        [KerberosIgnore]
        public short UpnLength { get; set; }

        [KerberosIgnore]
        public short UpnOffset { get; set; }

        [KerberosIgnore]
        public short DnsDomainNameLength { get; set; }

        [KerberosIgnore]
        public short DnsDomainNameOffset { get; set; }

        public UpnDomainFlags Flags { get; set; }

        public override PacType PacType => PacType.UPN_DOMAIN_INFO;
    }
}