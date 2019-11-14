using System.Buffers.Binary;
using System.Diagnostics;

namespace Kerberos.NET.Ndr
{
    public enum EndianType : byte
    {
        Big = 0x0,
        Little = 0x10
    }

    public sealed class RpcHeader
    {
        public const int PROTOCOL_VERSION = 1;
        public const int COMMON_HEADER_BYTES = 8;
        public const int HeaderLength = 16;

        private const int ExpectedFiller = unchecked((int)0xcccccccc);
        private const int ObjectLengthPlaceholder = unchecked((int)0xFFFFFFFF);

        private RpcHeader() { }

        public byte Version { get; private set; } = 1;

        public EndianType Endian { get; private set; } = EndianType.Little;

        public int CommonHeaderLength { get; private set; }

        public int Filler { get; private set; } = ExpectedFiller;

        public int ObjectBufferLength { get; set; }

        public int ConstructedTypeFiller { get; private set; }

        public static void WriteHeader(NdrBuffer buffer)
        {
            buffer.WriteByte(PROTOCOL_VERSION);
            buffer.WriteByte((byte)EndianType.Little);
            buffer.WriteInt16LittleEndian(COMMON_HEADER_BYTES);
            buffer.WriteInt32LittleEndian(ExpectedFiller);
            buffer.WriteInt32LittleEndian(ObjectLengthPlaceholder);
            buffer.WriteInt32LittleEndian(0);
        }

        public static bool TryReadHeader(NdrBuffer original, out RpcHeader header)
        {
            header = new RpcHeader();

            if (original.BytesAvailable < HeaderLength)
            {
                return false;
            }

            var buffer = original.Read(HeaderLength);

            if (buffer.Length < HeaderLength)
            {
                return false;
            }

            header.Version = buffer[0];

            if (header.Version != PROTOCOL_VERSION)
            {
                return false;
            }

            header.Endian = (EndianType)buffer[1];

            if (header.Endian != EndianType.Big && header.Endian != EndianType.Little)
            {
                return false;
            }

            header.CommonHeaderLength = BinaryPrimitives.ReadInt16LittleEndian(buffer.Slice(2, 2));

            if (header.CommonHeaderLength != COMMON_HEADER_BYTES)
            {
                return false;
            }

            header.Filler = BinaryPrimitives.ReadInt32LittleEndian(buffer.Slice(4, 4));

            Debug.Assert(header.Filler == ExpectedFiller);

            header.ObjectBufferLength = BinaryPrimitives.ReadInt32LittleEndian(buffer.Slice(8, 4));

            Debug.Assert(header.ObjectBufferLength == original.BytesAvailable);

            header.ConstructedTypeFiller = BinaryPrimitives.ReadInt32LittleEndian(buffer.Slice(12, 4));

            Debug.Assert(header.ConstructedTypeFiller == 0);

            return true;
        }
    }
}
