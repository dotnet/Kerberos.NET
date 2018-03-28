using Kerberos.NET.Entities.Authorization;
using System.IO;

namespace Kerberos.NET.Entities
{
    public class ClaimsSetMetadata : NdrMessage
    {
        public ClaimsSetMetadata(byte[] data)
        {
            if (data.Length <= 0)
            {
                return;
            }

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

            if (size != ClaimSetSize)
            {
                throw new InvalidDataException($"Data length {size} doesn't match expected ClaimSetSize {ClaimSetSize}");
            }

            var claimSet = pacStream.Read(ClaimSetSize);

            if (CompressionFormat != CompressionFormat.COMPRESSION_FORMAT_NONE)
            {
                claimSet = Compressions.Decompress(claimSet, UncompressedClaimSetSize, CompressionFormat);
            }

            ClaimsSet = new ClaimsSet(claimSet);

            ReservedField = pacStream.Read(ReservedFieldSize);
        }

        [KerberosIgnore]
        public int ClaimSetSize { get; private set; }

        public ClaimsSet ClaimsSet { get; private set; }

        public CompressionFormat CompressionFormat { get; private set; }

        [KerberosIgnore]
        public int UncompressedClaimSetSize { get; private set; }

        public short ReservedType { get; private set; }

        [KerberosIgnore]
        public int ReservedFieldSize { get; private set; }

        public byte[] ReservedField { get; private set; }
    }
}