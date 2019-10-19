using Kerberos.NET.Entities.Pac;
using System.Text;

#pragma warning disable S2344 // Enumeration type names should not have "Flags" or "Enum" suffixes

namespace Kerberos.NET.Entities
{
    public enum UpnDomainFlags
    {
        U = 1
    }

    public class UpnDomainInfo : NdrObject, IPacElement
    {
        public override void WriteBody(NdrBinaryStream stream)
        {
            var upnBytes = Encoding.Unicode.GetBytes(Upn);
            var domainBytes = Encoding.Unicode.GetBytes(Domain);

            stream.WriteShort((short)upnBytes.Length);
            stream.WriteShort(2 + 2 + 2 + 2 + 4 + 4); // + 4 to align on 8 boundary

            stream.WriteShort((short)domainBytes.Length);
            stream.WriteShort((short)(2 + 2 + 2 + 2 + 4 + 4 + upnBytes.Length));

            stream.WriteUnsignedInt((int)Flags);

            stream.Align(8);

            stream.WriteBytes(upnBytes);

            stream.Align(8);

            stream.WriteBytes(domainBytes);
        }

        public override void ReadBody(NdrBinaryStream stream)
        {
            UpnLength = stream.ReadShort();
            UpnOffset = stream.ReadShort();

            DnsDomainNameLength = stream.ReadShort();
            DnsDomainNameOffset = stream.ReadShort();

            Flags = (UpnDomainFlags)stream.ReadInt();

            stream.Align(8);

            Upn = Encoding.Unicode.GetString(stream.Read(UpnLength));

            stream.Align(8);

            Domain = Encoding.Unicode.GetString(stream.Read(DnsDomainNameLength));
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

        public PacType PacType => PacType.UPN_DOMAIN_INFO;
    }
}