using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;

namespace Kerberos.NET.Entities.Authorization
{
    public enum ClaimType
    {
        CLAIM_TYPE_INT64 = 1,
        CLAIM_TYPE_UINT64 = 2,
        CLAIM_TYPE_STRING = 3,
        CLAIM_TYPE_BOOLEAN = 6
    }

    [DebuggerDisplay("{Id}")]
    public class ClaimEntry
    {
        public ClaimEntry(NdrBinaryReader pacStream)
        {
            pacStream.Seek(4);

            Type = (ClaimType)pacStream.ReadShort();

            pacStream.Align(4);

            Count = pacStream.ReadUnsignedInt();

            pacStream.Seek(4);
        }

        public string Id { get; private set; }

        public ClaimType Type { get; private set; }

        public uint Count { get; private set; }

        private object[] values;

        public IEnumerable<T> GetValues<T>()
        {
            return values.Select(v => (T)Convert.ChangeType(v, typeof(T)));
        }

        internal void ReadValue(NdrBinaryReader pacStream)
        {
            Id = pacStream.ReadString();

            pacStream.Align(4);

            var count = pacStream.ReadInt();

            if (count != Count)
            {
                throw new InvalidDataException($"ValueCount {Count} doesn't match actual count {count} for claim {Id}.");
            }

            if (Type == ClaimType.CLAIM_TYPE_STRING)
            {
                var ptr = pacStream.ReadInt();

                if (count > 1 && ptr != 0)
                {
                    pacStream.Seek(8);
                }
            }

            ReadValues(pacStream);
        }

        private void ReadValues(NdrBinaryReader pacStream)
        {
            values = new object[Count];

            for (var i = 0; i < Count; i++)
            {
                switch (Type)
                {
                    case ClaimType.CLAIM_TYPE_BOOLEAN:
                        values[i] = Convert.ToBoolean(pacStream.ReadLong());
                        break;
                    case ClaimType.CLAIM_TYPE_INT64:
                        values[i] = pacStream.ReadLong();
                        break;
                    case ClaimType.CLAIM_TYPE_UINT64:
                        values[i] = (ulong)pacStream.ReadLong();
                        break;
                    case ClaimType.CLAIM_TYPE_STRING:
                        values[i] = pacStream.ReadString();
                        break;
                }
            }
        }
    }
}
