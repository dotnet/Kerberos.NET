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

    [DebuggerDisplay("{Id} {Type} {Count} {RawValues}")]
    public class ClaimEntry : NdrObject
    {
        public override void WriteBody(NdrBinaryStream stream)
        {

        }

        public override void WriteBody(NdrBinaryStream stream, Queue<Action> deferredFurther)
        {
            stream.WriteClaimEntry(this, deferredFurther);
        }
        
        internal void EncodeType(object val, ClaimType type, NdrBinaryStream stream)
        {
            if (type == ClaimType.CLAIM_TYPE_STRING)
            {
                stream.WriteString(val.ToString());
            }
            else
            {
                stream.WriteUnsignedLong(Convert.ToInt64(val));
            }
        }
        
        public string Id { get; private set; }

        public ClaimType Type { get; set; }

        [KerberosIgnore]
        public uint Count { get; set; }

        private object[] values;

        public IEnumerable<object> RawValues { get { return values; } }

        public IEnumerable<T> GetValues<T>()
        {
            return values.Select(v => (T)Convert.ChangeType(v, typeof(T)));
        }

        internal void ReadValue(NdrBinaryStream stream)
        {
            Id = stream.ReadString();

            stream.Align(4);

            var count = stream.ReadInt();

            if (count != Count)
            {
                throw new InvalidDataException($"ValueCount {Count} doesn't match actual count {count} for claim {Id}.");
            }

            ReadValues(stream);
        }

        private void ReadValues(NdrBinaryStream stream)
        {
            if (Type == ClaimType.CLAIM_TYPE_STRING)
            {
                var pointers = new int[Count];

                for (var i = 0; i < Count; i++)
                {
                    pointers[i] = stream.ReadInt();
                }
            }

            values = new object[Count];

            for (var i = 0; i < Count; i++)
            {
                switch (Type)
                {
                    case ClaimType.CLAIM_TYPE_BOOLEAN:
                        values[i] = Convert.ToBoolean(stream.ReadLong());
                        break;
                    case ClaimType.CLAIM_TYPE_INT64:
                        values[i] = stream.ReadLong();
                        break;
                    case ClaimType.CLAIM_TYPE_UINT64:
                        values[i] = (ulong)stream.ReadLong();
                        break;
                    case ClaimType.CLAIM_TYPE_STRING:
                        values[i] = stream.ReadString();
                        break;
                }
            }
        }

        public override void ReadBody(NdrBinaryStream stream)
        {
            stream.Seek(4); // offset for Id

            Type = (ClaimType)stream.ReadShort();

            stream.Align(4);

            Count = stream.ReadUnsignedInt();

            stream.Seek(4); // offset to values
        }
    }
}
