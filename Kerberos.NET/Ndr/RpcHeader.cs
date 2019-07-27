using System;
using System.IO;
using System.Linq;

namespace Kerberos.NET.Entities.Pac
{
    public class RpcHeader
    {
        private static class NdrConstants
        {
            public const int PROTOCOL_VERSION = 1;
            public const int COMMON_HEADER_BYTES = 8;
        }

        public RpcHeader(NdrBinaryStream pacStream)
        {
            ReadCommonHeader(pacStream);

            pacStream.Read(4);
            pacStream.Read(8);
            pacStream.Read(4);
        }

        internal RpcHeader() { }

        public byte Version { get; private set; }

        public bool Endian { get; private set; }

        public byte Encoding { get; private set; }

        public int Length { get; private set; }

        public void WriteCommonHeader(NdrBinaryStream stream)
        {
            stream.WriteBytes(new byte[] { NdrConstants.PROTOCOL_VERSION });

            byte headerBits = 0;

            headerBits |= Convert.ToByte(Encoding);
            headerBits |= (byte)((1 << 4) & Convert.ToByte(Endian));

            stream.WriteBytes(new byte[] { headerBits });

            stream.WriteShort(NdrConstants.COMMON_HEADER_BYTES);
            stream.WriteBytes(Enumerable.Repeat((byte)0, 4 + 8 + 4).ToArray());
        }

        private void ReadCommonHeader(NdrBinaryStream pacStream)
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
