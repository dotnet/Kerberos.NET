using Kerberos.NET.Crypto;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;

namespace Kerberos.NET.Entities.Pac
{
    [DebuggerDisplay("{Position} / {Length}")]
    public class NdrBinaryStream
    {
        // This turns out to be a big messy pile of bad code
        //
        // Manually parsing the NDR format is doable, but manually encoding the NDR is pretty terrible and error prone.
        // This works so far by shear luck and stupidity. This will not scale to more complicated structures.
        //
        // TODO: go find a real NDR encoder/decoder and use that instead

        private readonly BinaryReader reader;
        private readonly BinaryWriter writer;

        private readonly MemoryStream stream;

        private readonly Queue<Action> deferredWrites = new Queue<Action>();

        public NdrBinaryStream()
        {
            stream = new MemoryStream();
            writer = new BinaryWriter(stream);
        }

        private NdrBinaryStream(BinaryReader reader)
        {
            this.reader = reader;
        }

        public ReadOnlyMemory<byte> ToMemory()
        {
            return stream.ToArray();
        }

        internal void WriteDeferred()
        {
            Debug.WriteLine("...writing deferred...");

            while (deferredWrites.TryDequeue(out Action action))
            {
                action();
            }

            Debug.WriteLine("...done deferred...");
        }

        public NdrBinaryStream(byte[] bufferData)
            : this(new BinaryReader(new MemoryStream(bufferData)))
        {
        }

        public long Position
        {
            get
            {
                if (reader != null) { return reader.BaseStream.Position; }
                if (writer != null) { return writer.BaseStream.Position; }

                return 0;
            }
        }

        public long Length
        {
            get
            {
                if (reader != null) { return reader.BaseStream.Length; }
                if (writer != null) { return writer.BaseStream.Length; }

                return 0;
            }
        }

        public void Align(int mask)
        {
            long position = 0;

            if (reader != null)
            {
                position = reader.BaseStream.Position;
            }

            if (writer != null)
            {
                position = writer.BaseStream.Position;
            }

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
            var ticks = value.UtcTicks - FileTimeOffset;

            var low = ticks & 0xFFFFFFFF;
            var high = ticks >> 32;

            WriteUnsignedInt((int)low);
            WriteUnsignedInt((int)high);
        }

        private int referentCount = 0x20004;

        private bool WriteReferent(object val)
        {
            if (val == null)
            {
                WriteUnsignedInt(0);
                return false;
            }
            else
            {
                WriteUnsignedInt(referentCount);
                referentCount += 4;
                return true;
            }
        }

        public void WriteDeferredArray(IEnumerable<object> array, bool complex, Action<object, NdrBinaryStream> encoder)
        {
            WriteUnsignedInt(array?.Count() ?? 0);

            if (complex)
            {
                for (var i = 0; i < array.Count(); i++)
                {
                    WriteReferent(array.ElementAt(i));
                }
            }

            foreach (var item in array)
            {
                encoder(item, this);
            }
        }

        public void WriteDeferredArray<T>(IEnumerable<T> array, Queue<Action> deferredFurther = null)
            where T : NdrObject
        {
            WriteUnsignedInt(array?.Count() ?? 0);

            if (WriteReferent(array))
            {
                deferredWrites.Enqueue(() =>
                {
                    WriteUnsignedInt(array.Count());

                    foreach (var item in array)
                    {
                        item.WriteBody(this, deferredFurther);
                    }
                });
            }
        }

        public void WriteDeferredBytes(byte[] val)
        {
            WriteUnsignedInt(val?.Length ?? 0);

            if (WriteReferent(val))
            {
                deferredWrites.Enqueue(() =>
                {
                    WriteUnsignedInt(val.Length);
                    WriteBytes(val);
                });
            }
        }

        internal void WriteDeferredString(string val, Queue<Action> deferred = null)
        {
            var bytes = Encoding.Unicode.GetBytes(val);

            WriteReferent(bytes);

            var deferral = deferred ?? deferredWrites;

            deferral.Enqueue(() => WriteString(bytes));
        }

        internal void WriteRPCUnicodeString(string val)
        {
            if (val == null)
            {
                val = "";
            }

            var bytes = Encoding.Unicode.GetBytes(val);

            // length
            WriteShort((short)bytes.Length);
            // max length
            WriteShort((short)(bytes.Length * 2));

            // pointer
            WriteReferent(bytes);

            deferredWrites.Enqueue(() => WriteString(bytes));
        }

        internal void WriteRids(IEnumerable<SecurityIdentifier> sids)
        {
            WriteUnsignedInt(sids?.Count() ?? 0);

            if (WriteReferent(sids))
            {
                deferredWrites.Enqueue(() =>
                {
                    WriteUnsignedInt(sids.Count());

                    foreach (var sid in sids)
                    {
                        WriteRid(sid);
                        WriteUnsignedInt((int)sid.Attributes);
                    }
                });
            }
        }

        internal void WriteSids(IEnumerable<SecurityIdentifier> extraSids, string debug)
        {
            // count
            // defer

            // real count
            // for count
            //  defer sid write
            //  write attribute

            Align(4);

            WriteUnsignedInt(extraSids?.Count() ?? 0);

            if (WriteReferent(extraSids))
            {
                Debug.WriteLine("[WriteSids] " + debug);

                deferredWrites.Enqueue(() =>
                {
                    WriteUnsignedInt(extraSids.Count());

                    var localQueue = new Queue<SecurityIdentifier>();

                    foreach (var sid in extraSids)
                    {
                        //WriteSid(sid, debug);

                        if (WriteReferent(sid))
                        {
                            localQueue.Enqueue(sid);
                            WriteUnsignedInt((int)sid.Attributes);
                        }
                    }

                    while (localQueue.TryDequeue(out SecurityIdentifier sid2))
                    {
                        Debug.WriteLine("[Deferred WriteSid] " + debug);
                        var len = (sid2.BinaryForm.Length - 8) / 4;

                        WriteUnsignedInt(len);
                        WriteBytes(sid2.BinaryForm);
                    }
                });
            }
        }

        public void WriteString(string value)
        {
            WriteString(Encoding.Unicode.GetBytes(value));
        }

        private void WriteString(byte[] value)
        {
            var total = value.Length / 2;

            // total
            WriteUnsignedInt(total);

            // unused
            WriteUnsignedInt(0);

            // used
            WriteUnsignedInt(total);

            WriteBytes(value);
        }

        public void WriteUnsignedLong(long value)
        {
            Align(8);
            writer.Write(value);
        }

        public void WriteUnsignedInt(int value)
        {
            Align(4);
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

        public NdrString ReadRPCUnicodeString()
        {
            var length = ReadShort();
            var maxLength = ReadShort();
            var pointer = ReadInt();

            return new NdrString(length, maxLength, pointer);
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

        public void WriteRid(SecurityIdentifier value)
        {
            if (value == null)
            {
                throw new ArgumentException("SecurityIdentifier cannot be null");
            }

            var lastAuthority = value.SubAuthorities.Last();

            var bytes = new byte[4];

            Endian.ConvertToLittleEndian(lastAuthority, bytes);

            writer.Write(bytes);
        }

        public void WriteSid(SecurityIdentifier value, string debug)
        {
            Debug.WriteLine("[WriteSid] " + debug);

            if (WriteReferent(value))
            {
                deferredWrites.Enqueue(() =>
                {
                    Debug.WriteLine("[Deferred WriteSid] " + debug);
                    var len = (value.BinaryForm.Length - 8) / 4;

                    WriteUnsignedInt(len);
                    WriteBytes(value.BinaryForm);
                });
            }
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

            var bytes = new byte[8 + (sidSize * 4)];
            Read(bytes);

            return new SecurityIdentifier(bytes);
        }

        public long Seek(int n)
        {
            if (reader != null)
            {
                return reader.BaseStream.Seek(n, SeekOrigin.Current);
            }
            else
            {
                return writer.BaseStream.Seek(n, SeekOrigin.Current);
            }
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

        internal void WriteClaimsArray(ClaimsArray array)
        {
            WriteUnsignedInt((int)array.ClaimSource);

            Queue<Action> deferred = new Queue<Action>();

            WriteDeferredArray(array.ClaimEntries, deferred);

            deferredWrites.Enqueue(() =>
            {
                while (deferred.TryDequeue(out Action action))
                {
                    action();
                }
            });
            //WriteDeferredArray(array.ClaimEntries, false, (c, s) => ((ClaimEntry)c).WriteDeferred(s));
        }

        internal void WriteClaimEntry(ClaimEntry claim, Queue<Action> deferred)
        {
            WriteDeferredString(claim.Id, deferred);

            WriteUnsignedInt((int)claim.Type);

            WriteUnsignedInt(claim.RawValues.Count());

            WriteReferent(deferred);

            deferred.Enqueue(() =>
            {
                WriteDeferredArray(claim.RawValues, claim.Type == ClaimType.CLAIM_TYPE_STRING, (v, str) => claim.EncodeType(v, claim.Type, str));
            });
        }
    }
}
