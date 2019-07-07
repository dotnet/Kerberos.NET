using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;

namespace Kerberos.NET.Entities.Pac
{
    public enum ClaimType
    {
        CLAIM_TYPE_INT64 = 1,
        CLAIM_TYPE_UINT64 = 2,
        CLAIM_TYPE_STRING = 3,
        CLAIM_TYPE_BOOLEAN = 6
    }

    [DebuggerDisplay("{Id}")]
    public class ClaimEntry : NdrObject
    {
        public ClaimEntry(NdrBinaryReader stream)
            : base(stream)
        {
            Stream.Seek(4);

            Type = (ClaimType)Stream.ReadShort();

            Stream.Align(4);

            Count = Stream.ReadUnsignedInt();

            Stream.Seek(4);
        }

        public string Id { get; private set; }

        public ClaimType Type { get; }

        [KerberosIgnore]
        public uint Count { get; }

        private object[] values;

        public IEnumerable<object> RawValues { get { return values; } }

        public IEnumerable<T> GetValues<T>()
        {
            return values.Select(v => (T)Convert.ChangeType(v, typeof(T)));
        }

        internal void ReadValue(NdrBinaryReader stream)
        {
            Id = stream.ReadString();

            stream.Align(4);

            var count = stream.ReadInt();

            if (count != Count)
            {
                throw new InvalidDataException($"ValueCount {Count} doesn't match actual count {count} for claim {Id}.");
            }

            if (Type == ClaimType.CLAIM_TYPE_STRING)
            {
                var ptr = stream.ReadInt();

                if (count > 1 && ptr != 0)
                {
                    stream.Seek(8);
                }
            }

            ReadValues(stream);
        }

        private void ReadValues(NdrBinaryReader Stream)
        {
            values = new object[Count];

            for (var i = 0; i < Count; i++)
            {
                switch (Type)
                {
                    case ClaimType.CLAIM_TYPE_BOOLEAN:
                        values[i] = Convert.ToBoolean(Stream.ReadLong());
                        break;
                    case ClaimType.CLAIM_TYPE_INT64:
                        values[i] = Stream.ReadLong();
                        break;
                    case ClaimType.CLAIM_TYPE_UINT64:
                        values[i] = (ulong)Stream.ReadLong();
                        break;
                    case ClaimType.CLAIM_TYPE_STRING:
                        values[i] = Stream.ReadString();
                        break;
                }
            }
        }
    }
}
