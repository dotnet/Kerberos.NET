using System;
using System.IO;

namespace Kerberos.NET.Entities.Authorization
{
    public class RpcHeader
    {
        private static class NdrConstants
        {
            public const int PROTOCOL_VERSION = 1;
            public const int COMMON_HEADER_BYTES = 8;
        }

        public RpcHeader(NdrBinaryReader pacStream)
        {
            ReadCommonHeader(pacStream);

            pacStream.Read(4);
            pacStream.Read(8);
            pacStream.Read(4);
        }

        public byte Version { get; private set; }

        public bool Endian { get; private set; }

        public byte Encoding { get; private set; }

        public int Length { get; private set; }

        private void ReadCommonHeader(NdrBinaryReader pacStream)
        {
            Version = pacStream.Read(1)[0];

            if (Version != NdrConstants.PROTOCOL_VERSION)
            {
                throw new InvalidDataException($"Unknown Protocol version {Version}");
            }

            var headerBits = pacStream.Read(1)[0];

            var endian = headerBits >> 4 & 0x0F;

            if (endian != 0 && endian != 1)
            {
                throw new InvalidDataException($"Unknown endianness {endian}");
            }

            Endian = Convert.ToBoolean(endian);

            Encoding = (byte)(headerBits & 0x0F);

            if (Encoding != 0 && Encoding != 1)
            {
                throw new InvalidDataException($"Unknown encoding {Encoding}");
            }

            Length = pacStream.ReadShort();

            if (Length != NdrConstants.COMMON_HEADER_BYTES)
            {
                throw new InvalidDataException($"Unknown common header length {Length}");
            }
        }
    }
}
