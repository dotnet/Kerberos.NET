using Kerberos.NET.Entities.Pac;
using Kerberos.NET.Ndr;
using System;
using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text;

#pragma warning disable S2344 // Enumeration type names should not have "Flags" or "Enum" suffixes

namespace Kerberos.NET.Entities
{
    public enum UpnDomainFlags
    {
        U = 1
    }

    public class UpnDomainInfo : PacObject
    {
        public override ReadOnlySpan<byte> Marshal()
        {
            var buffer = new NdrBuffer();

            var upnBytes = Encoding.Unicode.GetBytes(Upn);
            var domainBytes = Encoding.Unicode.GetBytes(Domain);

            buffer.WriteInt16LittleEndian((short)upnBytes.Length);
            buffer.WriteInt16LittleEndian(2 + 2 + 2 + 2 + 4 + 4); // + 4 to align on 8 boundary

            buffer.WriteInt16LittleEndian((short)domainBytes.Length);
            buffer.WriteInt16LittleEndian((short)(2 + 2 + 2 + 2 + 4 + 4 + upnBytes.Length));

            buffer.WriteInt32LittleEndian((int)Flags);

            buffer.WriteInt32LittleEndian(0);
            buffer.WriteFixedPrimitiveArray(upnBytes);

            buffer.WriteInt32LittleEndian(0);
            buffer.WriteFixedPrimitiveArray(domainBytes);

            return buffer.ToSpan();
        }

        public override void Unmarshal(ReadOnlyMemory<byte> bytes)
        {
            var span = bytes.Span;

            UpnLength = BinaryPrimitives.ReadInt16LittleEndian(span.Slice(0, 2));
            UpnOffset = BinaryPrimitives.ReadInt16LittleEndian(span.Slice(2, 2));

            DnsDomainNameLength = BinaryPrimitives.ReadInt16LittleEndian(span.Slice(4, 2));
            DnsDomainNameOffset = BinaryPrimitives.ReadInt16LittleEndian(span.Slice(6, 2));

            Flags = (UpnDomainFlags)BinaryPrimitives.ReadInt32LittleEndian(span.Slice(8, 4));

            Upn = MemoryMarshal.Cast<byte, char>(span.Slice(UpnOffset, UpnLength)).ToString();

            Domain = MemoryMarshal.Cast<byte, char>(span.Slice(DnsDomainNameOffset, DnsDomainNameLength)).ToString();
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
