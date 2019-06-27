using Kerberos.NET.Asn1;
using System.Collections.Generic;
using System.IO;

namespace Kerberos.NET.Entities.Pac
{
    public enum ClaimSourceType
    {
        CLAIMS_SOURCE_TYPE_AD = 1,
        CLAIMS_SOURCE_TYPE_CERTIFICATE
    }

    public class ClaimsArray : NdrObject
    {
        public ClaimsArray(NdrBinaryReader stream)
            : base(stream)
        {
            ClaimSource = (ClaimSourceType)Stream.ReadInt();
            Count = Stream.ReadUnsignedInt();

            var claims = new List<ClaimEntry>();

            Stream.Seek(4);

            var count = Stream.ReadInt();

            if (Count != count)
            {
                throw new InvalidDataException($"Claims count {Count} doesn't match actual count {count}");
            }

            for (var i = 0; i < Count; i++)
            {
                claims.Add(new ClaimEntry(Stream));
            }

            foreach (var entry in claims)
            {
                entry.ReadValue(Stream);
            }

            ClaimEntries = claims;
        }

        public ClaimSourceType ClaimSource { get; }

        [KerberosIgnore]
        public uint Count { get; }

        public IEnumerable<ClaimEntry> ClaimEntries { get; }
    }
}
