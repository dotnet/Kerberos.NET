using Kerberos.NET.Entities.Pac;
using System.IO;

namespace Kerberos.NET.Entities
{
    public class ClaimsSetMetadata : NdrMessage
    {
        public ClaimsSetMetadata(byte[] data)
            : base(data)
        {
            ClaimSetSize = Stream.ReadInt();

            Stream.Seek(4);

            CompressionFormat = (CompressionFormat)Stream.ReadInt();
            UncompressedClaimSetSize = Stream.ReadInt();
            ReservedType = Stream.ReadShort();
            ReservedFieldSize = Stream.ReadInt();

            Stream.Align(8);

            var size = Stream.ReadInt();

            if (size != ClaimSetSize)
            {
                throw new InvalidDataException($"Data length {size} doesn't match expected ClaimSetSize {ClaimSetSize}");
            }

            var claimSet = Stream.Read(ClaimSetSize);

            if (CompressionFormat != CompressionFormat.COMPRESSION_FORMAT_NONE)
            {
                claimSet = Compressions.Decompress(claimSet, UncompressedClaimSetSize, CompressionFormat);
            }

            ClaimsSet = new ClaimsSet(claimSet);

            ReservedField = Stream.Read(ReservedFieldSize);
        }

        [KerberosIgnore]
        public int ClaimSetSize { get; }

        public ClaimsSet ClaimsSet { get; }

        public CompressionFormat CompressionFormat { get; }

        [KerberosIgnore]
        public int UncompressedClaimSetSize { get; }

        public short ReservedType { get; }

        [KerberosIgnore]
        public int ReservedFieldSize { get; }

        public byte[] ReservedField { get; }
    }
}