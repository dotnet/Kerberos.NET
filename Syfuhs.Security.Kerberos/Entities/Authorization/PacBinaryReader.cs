using System;
using System.IO;
using System.Security.Principal;

namespace Syfuhs.Security.Kerberos.Entities.Authorization
{
    public class PacBinaryReader
    {
        private readonly BinaryReader reader;

        public PacBinaryReader(Stream stream)
        {
            reader = new BinaryReader(stream);
        }

        public PacBinaryReader(byte[] bufferData)
            : this(new MemoryStream(bufferData))
        {
        }

        public void Align(int mask)
        {
            var position = reader.BaseStream.Position;
            var shift = position & mask - 1;

            if (mask != 0 && shift != 0)
            {
                var seek = mask - shift;

                Seek((int)seek);
            }
        }

        public byte[] Read(int length)
        {
            return reader.ReadBytes(length);
        }

        public void Read(byte[] b)
        {
            reader.Read(b, 0, b.Length);
        }

        public char ReadChar()
        {
            Align(2);

            return reader.ReadChar();
        }

        public short ReadShort()
        {
            Align(2);

            return reader.ReadInt16();
        }

        public int ReadInt()
        {
            Align(4);

            return reader.ReadInt32();
        }

        public long ReadLong()
        {
            Align(8);

            return reader.ReadInt64();
        }

        public uint ReadUnsignedInt()
        {
            return reader.ReadUInt32();
        }

        private const long TicksPerDay = 864000000000L;
        private const long DaysTo1601 = 584388;
        private const long FileTimeOffset = DaysTo1601 * TicksPerDay;

        public DateTimeOffset ReadFiletime()
        {
            var low = ReadUnsignedInt();
            var high = ReadUnsignedInt();

            if (low != 0xffffffffL && high != 0x7fffffffL)
            {
                var fileTime = (high << 32) + low;

                var universalTicks = fileTime + FileTimeOffset;


                return new DateTimeOffset((long)universalTicks, TimeSpan.Zero);
            }

            return DateTimeOffset.MinValue;
        }

        public PacString ReadRPCUnicodeString()
        {
            var length = ReadShort();
            var maxLength = ReadShort();
            var pointer = ReadInt();

            return new PacString(length, maxLength, pointer);
        }

        public string ReadString()
        {
            var total = ReadInt();
            var unused = ReadInt();
            var used = ReadInt();

            if (unused > total || used > total - unused)
            {
                throw new InvalidDataException(
                    $"ReadString failed with weird results. Total: {total}; Unused: {unused}; Used: {used}"
                );
            }

            reader.BaseStream.Seek(unused * 2, SeekOrigin.Current);

            var chars = new char[used];

            for (var l = 0; l < used; l++)
            {
                chars[l] = ReadChar();
            }

            return new string(chars);
        }

        public SecurityIdentifier ReadRid()
        {
            var bytes = new byte[4];
            Read(bytes);

            var sidBytes = new byte[8 + bytes.Length];

            sidBytes[0] = 1;
            sidBytes[1] = (byte)(bytes.Length / 4);

            Buffer.BlockCopy(new byte[] { 0, 0, 0, 0, 0, 5 }, 0, sidBytes, 2, 6);
            Buffer.BlockCopy(bytes, 0, sidBytes, 8, bytes.Length);

            return new SecurityIdentifier(sidBytes, 0);
        }

        public SecurityIdentifier ReadSid()
        {
            var sidSize = ReadInt();

            var bytes = new byte[8 + sidSize * 4];
            Read(bytes);

            return new SecurityIdentifier(bytes, 0);
        }

        public long Seek(int n)
        {
            return reader.BaseStream.Seek(n, SeekOrigin.Current);
        }

        public long JumpToAddress(int n)
        {
            return reader.BaseStream.Seek(n, SeekOrigin.Begin);
        }

        internal byte[] ReadToEnd()
        {
            var left = reader.BytesAvailable();

            return reader.ReadBytes((int)left);
        }
    }
}
