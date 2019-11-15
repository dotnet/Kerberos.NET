using Kerberos.NET.Ndr;
using System.Diagnostics;

namespace Kerberos.NET.Entities.Pac
{
    [DebuggerDisplay("{RelativeId} {Attributes}")]
    public class GroupMembership : INdrStruct
    {
        public int RelativeId;

        public SidAttributes Attributes;

        public void Marshal(NdrBuffer buffer)
        {
            buffer.WriteInt32LittleEndian(RelativeId);
            buffer.WriteInt32LittleEndian((int)Attributes);
        }

        public void Unmarshal(NdrBuffer buffer)
        {
            RelativeId = buffer.ReadInt32LittleEndian();
            Attributes = (SidAttributes)buffer.ReadInt32LittleEndian();
        }
    }
}
