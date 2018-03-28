using System.Collections.Generic;
using System.IO;

namespace Kerberos.NET.Entities.Authorization
{
    public enum ClaimSourceType
    {
        CLAIMS_SOURCE_TYPE_AD = 1,
        CLAIMS_SOURCE_TYPE_CERTIFICATE
    }

    public class ClaimsArray
    {
        public ClaimsArray(NdrBinaryReader pacStream)
        {
            ClaimSource = (ClaimSourceType)pacStream.ReadInt();
            Count = pacStream.ReadUnsignedInt();

            var claims = new List<ClaimEntry>();

            pacStream.Seek(4);

            var count = pacStream.ReadInt();

            if (Count != count)
            {
                throw new InvalidDataException($"Claims count {Count} doesn't match actual count {count}");
            }

            for (var i = 0; i < Count; i++)
            {
                claims.Add(new ClaimEntry(pacStream));
            }

            foreach (var entry in claims)
            {
                entry.ReadValue(pacStream);
            }

            ClaimEntries = claims;
        }

        public ClaimSourceType ClaimSource { get; private set; }

        [KerberosIgnore]
        public uint Count { get; private set; }

        public IEnumerable<ClaimEntry> ClaimEntries { get; private set; }
    }
}
