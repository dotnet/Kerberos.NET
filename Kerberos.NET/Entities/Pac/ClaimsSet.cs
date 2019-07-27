using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Kerberos.NET.Entities.Pac
{
    public class ClaimsSet : NdrMessage
    {
        public override void WriteBody(NdrBinaryStream stream)
        {
            stream.WriteUnsignedInt(ClaimsArray.Count());
            stream.WriteDeferredArray(ClaimsArray);

            stream.WriteShort(ReservedType);
            stream.WriteUnsignedInt(ReservedFieldSize);
            stream.WriteBytes(ReservedField);
        }

        private IEnumerable<ClaimsArray> ReadClaimsArray(NdrBinaryStream stream)
        {
            var count = stream.ReadInt();

            if (count != Count)
            {
                throw new InvalidDataException($"Array count {Count} doesn't match actual count {count}");
            }

            var claims = new List<ClaimsArray>();

            for (var i = 0; i < Count; i++)
            {
                var array = new ClaimsArray();
                array.ReadBody(stream);

                claims.Add(array);
            }

            return claims;
        }

        public override void ReadBody(NdrBinaryStream stream)
        {
            Count = stream.ReadInt();

            stream.Seek(4);

            ReservedType = stream.ReadShort();
            ReservedFieldSize = stream.ReadInt();

            ReservedField = stream.Read(ReservedFieldSize);

            stream.Align(8);

            ClaimsArray = ReadClaimsArray(stream);
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
