using Kerberos.NET.Ndr;
using System.Collections.Generic;

namespace Kerberos.NET.Entities.Pac
{
    public enum ClaimSourceType
    {
        CLAIMS_SOURCE_TYPE_AD = 1,
        CLAIMS_SOURCE_TYPE_CERTIFICATE
    }

    public class ClaimsArray : INdrStruct
    {
        public void Marshal(NdrBuffer buffer)
        {
            buffer.WriteInt32LittleEndian((int)ClaimSource);

            buffer.WriteInt32LittleEndian(Count);

            buffer.WriteDeferredStructArray(ClaimEntries);
        }

        public void Unmarshal(NdrBuffer buffer)
        {
            ClaimSource = (ClaimSourceType)buffer.ReadInt32LittleEndian();
            Count = buffer.ReadInt32LittleEndian();

            buffer.ReadDeferredStructArray<ClaimEntry>(Count, v => ClaimEntries = v);
        }

        public ClaimSourceType ClaimSource { get; set; }

        [KerberosIgnore]
        public int Count { get; set; }

        public IEnumerable<ClaimEntry> ClaimEntries { get; set; }
    }
}
