using Kerberos.NET.Entities.Pac;
using System;
using System.Text;

namespace Kerberos.NET.Entities
{
    public class PacClientInfo : NdrObject, IPacElement
    {
        public DateTimeOffset ClientId { get; set; }

        [KerberosIgnore]
        public short NameLength { get; private set; }

        public string Name { get; set; }

        public PacType PacType => PacType.CLIENT_NAME_TICKET_INFO;

        public override void ReadBody(NdrBinaryStream stream)
        {
            ClientId = stream.ReadFiletime();
            NameLength = stream.ReadShort();
            Name = Encoding.Unicode.GetString(stream.Read(NameLength));
        }

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