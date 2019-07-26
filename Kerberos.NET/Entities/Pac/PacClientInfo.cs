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

        public DateTimeOffset ClientId { get; set; }

        [KerberosIgnore]
        public short NameLength { get; private set; }

        public string Name { get; set; }

        public override void WriteBody(NdrBinaryStream stream)
        {
            stream.WriteFiletime(ClientId);

            var name = Encoding.Unicode.GetBytes(Name);

            NameLength = (short)name.Length;

            stream.WriteShort(NameLength);
            stream.WriteBytes(name);
        }
    }
}