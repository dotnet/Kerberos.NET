using Kerberos.NET.Entities.Pac;
using System.Text;

#pragma warning disable S2344 // Enumeration type names should not have "Flags" or "Enum" suffixes

namespace Kerberos.NET.Entities
{
    public enum UpnDomainFlags
    {
        U = 1
    }

    public class UpnDomainInfo : NdrObject
    {
        public UpnDomainInfo(byte[] data)
            : base(data)
        {
            UpnLength = Stream.ReadShort();
            UpnOffset = Stream.ReadShort();

            DnsDomainNameLength = Stream.ReadShort();
            DnsDomainNameOffset = Stream.ReadShort();

            Flags = (UpnDomainFlags)Stream.ReadInt();

            Stream.Align(8);

            Upn = Encoding.Unicode.GetString(Stream.Read(UpnLength));

            Stream.Align(8);

            Domain = Encoding.Unicode.GetString(Stream.Read(DnsDomainNameLength));
        }

        public string Upn { get; }

        public string Domain { get; }

        [KerberosIgnore]
        public short UpnLength { get; }

        [KerberosIgnore]
        public short UpnOffset { get; }

        [KerberosIgnore]
        public short DnsDomainNameLength { get; }

        [KerberosIgnore]
        public short DnsDomainNameOffset { get; }

        public UpnDomainFlags Flags { get; }
    }
}