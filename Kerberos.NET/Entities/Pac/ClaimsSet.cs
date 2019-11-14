using Kerberos.NET.Ndr;
using System.Collections.Generic;
using System.Linq;

namespace Kerberos.NET.Entities.Pac
{
    public class ClaimsSet : NdrPacObject, INdrStruct
    {
        public override void Marshal(NdrBuffer buffer)
        {
            buffer.WriteInt32LittleEndian(ClaimsArray.Count());
            buffer.WriteDeferredStructArray(ClaimsArray);

            buffer.WriteInt16LittleEndian(ReservedType);
            buffer.WriteInt32LittleEndian(ReservedFieldSize);
            buffer.WriteDeferredConformantArray<byte>(ReservedField);
        }

        public override void Unmarshal(NdrBuffer buffer)
        {
            Count = buffer.ReadInt32LittleEndian();

            buffer.ReadDeferredStructArray<ClaimsArray>(Count, v => ClaimsArray = v);

            ReservedType = buffer.ReadInt16LittleEndian();
            ReservedFieldSize = buffer.ReadInt32LittleEndian();
            buffer.ReadDeferredConformantArray<byte>(ReservedFieldSize, v => ReservedField = v.ToArray());
        }

        [KerberosIgnore]
        public int Count { get; set; }

        public IEnumerable<ClaimsArray> ClaimsArray { get; set; }

        public short ReservedType { get; set; }

        [KerberosIgnore]
        public int ReservedFieldSize { get; set; }

        public byte[] ReservedField { get; set; }
    }
}
