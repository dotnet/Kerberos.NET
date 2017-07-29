using Syfuhs.Security.Kerberos.Entities.Authorization;

namespace Syfuhs.Security.Kerberos.Entities
{
    public class ClaimsSetMetadata : NdrMessage
    {
        public ClaimsSetMetadata(byte[] data)
        {
            var pacStream = new NdrBinaryReader(data);

            Header = new RpcHeader(pacStream);

            ClaimSetSize = pacStream.ReadInt();

            pacStream.Seek(4);

            CompressionFormat = (CompressionFormat)pacStream.ReadInt();
            UncompressedClaimSetSize = pacStream.ReadInt();
            ReservedType = pacStream.ReadShort();
            ReservedFieldSize = pacStream.ReadInt();

            pacStream.Align(8);
            var size = pacStream.ReadInt();

            var claimSet = pacStream.Read(ClaimSetSize);

            if (CompressionFormat != CompressionFormat.COMPRESSION_FORMAT_NONE)
            {
                claimSet = Compressions.Decompress(claimSet, UncompressedClaimSetSize, CompressionFormat);
            }

            ClaimsSet = new ClaimsSet(claimSet);

            ReservedField = pacStream.Read(ReservedFieldSize);
        }

        public int ClaimSetSize { get; private set; }

        public ClaimsSet ClaimsSet { get; private set; }

        public CompressionFormat CompressionFormat { get; private set; }

        public int UncompressedClaimSetSize { get; private set; }

        public short ReservedType { get; private set; }

        public int ReservedFieldSize { get; private set; }

        public byte[] ReservedField { get; private set; }
    }
}