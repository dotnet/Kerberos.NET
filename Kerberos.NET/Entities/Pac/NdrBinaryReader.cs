using Kerberos.NET.Crypto;
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;

namespace Kerberos.NET.Entities.Pac
{
    [DebuggerDisplay("{Position} / {Length}")]
    public class NdrBinaryStream
    {
        private readonly BinaryReader reader;
        private readonly BinaryWriter writer;

        private readonly MemoryStream stream;

        public NdrBinaryStream()
        {
            stream = new MemoryStream();
            writer = new BinaryWriter(stream);
        }

        private NdrBinaryStream(BinaryReader reader)
        {
            this.reader = reader;
        }

        public NdrBinaryStream(byte[] bufferData)
            : this(new BinaryReader(new MemoryStream(bufferData)))
        {
        }

        public long Position { get { return reader.BaseStream.Position; } }

        public long Length { get { return reader.BaseStream.Length; } }

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

        public RpcHeader ReadNdrHeader()
        {
            return new RpcHeader(this);
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

        public void WriteShort(short value)
        {
            writer.Write(value);
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

        public void WriteFiletime(DateTimeOffset value)
        {
            var low = value.UtcTicks & 0xFFFFFFFF;
            var high = value.UtcTicks >> 32;

            WriteUnsignedInt((int)low);
            WriteUnsignedInt((int)high);
        }

        internal void WriteRPCUnicodeString(string userName)
        {
            throw new NotImplementedException();
        }

        public void WriteUnsignedInt(int value)
        {
            writer.Write(value);
        }

        public DateTimeOffset ReadFiletime()
        {
            var low = ReadUnsignedInt();
            var high = ReadUnsignedInt();

            if (low != 0xffffffffL && high != 0x7fffffffL)
            {
                var fileTime = ((long)high << 32) + low;

                var universalTicks = fileTime + FileTimeOffset;


                return new DateTimeOffset(universalTicks, TimeSpan.Zero);
            }

            return DateTimeOffset.MinValue;
        }

        internal void WriteBytes(byte[] v)
        {
            writer.Write(v);
        }

        public PacString ReadRPCUnicodeString()
        {
            var length = ReadShort();
            var maxLength = ReadShort();
            var pointer = ReadInt();

            return new PacString(length, maxLength, pointer);
        }

        public string ReadString(int maxLength = int.MaxValue)
        {
            var total = ReadInt() * 2;
            var unused = ReadInt() * 2;
            var used = ReadInt() * 2;

            if (maxLength < total)
            {
                throw new InvalidDataException($"Max length of string {maxLength} is greater than total length {total}");
            }

            if (unused > total || used > total - unused)
            {
                throw new InvalidDataException(
                    $"ReadString failed with weird results. Total: {total}; Unused: {unused}; Used: {used}"
                );
            }

            reader.BaseStream.Seek(unused, SeekOrigin.Current);

            var chars = reader.ReadBytes(used);

            var readTo = chars.Length;

            if (readTo > 1 &&
                chars[chars.Length - 1] == '\0' &&
                chars[chars.Length - 2] == '\0')
            {
                readTo -= 2;
            }

            return Encoding.Unicode.GetString(chars, 0, readTo);
        }

        internal ReadOnlyMemory<byte> Encode()
        {
            throw new NotImplementedException();
        }

        public void WriteRid(SecurityIdentifier value)
        {
            var lastAuthority = value.SubAuthorities.Last();

            var bytes = new byte[4];

            Endian.ConvertToLittleEndian(lastAuthority, bytes);

            writer.Write(bytes);
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

            return new SecurityIdentifier(sidBytes);
        }

        public SecurityIdentifier ReadSid()
        {
            var sidSize = ReadInt();

            var bytes = new byte[8 + sidSize * 4];
            Read(bytes);

            return new SecurityIdentifier(bytes);
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
