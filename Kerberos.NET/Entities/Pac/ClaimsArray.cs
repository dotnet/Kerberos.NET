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
        public override void WriteBody(NdrBinaryStream stream)
        {
            stream.WriteClaimsArray(this);
        }

        public override void ReadBody(NdrBinaryStream stream)
        {
            ClaimSource = (ClaimSourceType)stream.ReadInt();
            Count = stream.ReadUnsignedInt();

            var claims = new List<ClaimEntry>();

            stream.Seek(4);

            var count = stream.ReadInt();

            if (Count != count)
            {
                throw new InvalidDataException($"Claims count {Count} doesn't match actual count {count}");
            }

            for (var i = 0; i < Count; i++)
            {
                var claim = new ClaimEntry();
                claim.ReadBody(stream);

                claims.Add(claim);
            }

            foreach (var entry in claims)
            {
                entry.ReadValue(stream);
            }

            ClaimEntries = claims;
        }

        public ClaimSourceType ClaimSource { get; set; }

        [KerberosIgnore]
        public uint Count { get; set; }

        public IEnumerable<ClaimEntry> ClaimEntries { get; set; }
    }
}
