using Kerberos.NET.Entities.Pac;
using System;
using System.Text;

namespace Kerberos.NET.Entities
{
    public class PacClientInfo : NdrObject
    {
        public PacClientInfo(byte[] data)
            : base(data)
        {
            ClientId = Stream.ReadFiletime();
            NameLength = Stream.ReadShort();
            Name = Encoding.Unicode.GetString(Stream.Read(NameLength));
        }

        public DateTimeOffset ClientId { get; }

        [KerberosIgnore]
        public short NameLength { get; }

        public string Name { get; }
    }
}