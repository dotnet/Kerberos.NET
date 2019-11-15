using Kerberos.NET.Entities.Pac;
using Kerberos.NET.Ndr;
using System;

namespace Kerberos.NET.Entities
{
    public class PacClientInfo : PacObject, IPacElement
    {
        public DateTimeOffset ClientId { get; set; }

        [KerberosIgnore]
        public short NameLength { get; private set; }

        public string Name { get; set; }

        public PacType PacType => PacType.CLIENT_NAME_TICKET_INFO;

        public override ReadOnlySpan<byte> Marshal()
        {
            var buffer = new NdrBuffer();

            buffer.WriteFiletime(ClientId);
            buffer.WriteInt16LittleEndian((short)(Name.Length * 2));

            if (NameLength > 0)
            {
                buffer.WriteFixedPrimitiveArray(Name.ToCharArray());
            }

            return buffer.ToSpan();
        }

        public override void Unmarshal(ReadOnlyMemory<byte> bytes)
        {
            var buffer = new NdrBuffer(bytes);

            ClientId = buffer.ReadFiletime();

            NameLength = buffer.ReadInt16LittleEndian();

            if (NameLength > 0)
            {
                Name = buffer.ReadFixedPrimitiveArray<char>(NameLength / 2).ToString();
            }
        }
    }
}
