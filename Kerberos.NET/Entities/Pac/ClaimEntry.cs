using Kerberos.NET.Ndr;
using System;
using System.Collections.Generic;
using System.Diagnostics;
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
    public class ClaimEntry : INdrStruct, INdrUnion
    {
        public void Marshal(NdrBuffer buffer)
        {
            buffer.WriteDeferredConformantVaryingArray(Id.AsMemory());

            buffer.WriteInt16LittleEndian((short)Type);
            buffer.WriteInt32LittleEndian(Count);

            buffer.WriteDeferredStructUnion(this);
        }

        public string Id { get; private set; }

        public ClaimType Type { get; set; }

        [KerberosIgnore]
        public int Count { get; set; }

        public IList<object> Values { get; set; }

        public IEnumerable<T> GetValues<T>()
        {
            return Values.Select(v => (T)Convert.ChangeType(v, typeof(T)));
        }

        public void Unmarshal(NdrBuffer buffer)
        {
            buffer.ReadDeferredConformantVaryingArray<char>(v => Id = v.ToString());

            Type = (ClaimType)buffer.ReadInt16LittleEndian();
            Count = buffer.ReadInt32LittleEndian();

            buffer.ReadDeferredStructUnion(this);
        }

        public void UnmarshalUnion(NdrBuffer buffer)
        {
            Values = new List<object>();

            var count = buffer.ReadInt32LittleEndian();

            switch (Type)
            {
                case ClaimType.CLAIM_TYPE_STRING:
                    buffer.ReadDeferredArray(count, () => Values.Add(buffer.ReadConformantVaryingCharArray().ToString()));
                    break;
                default:
                    Values = buffer.ReadFixedPrimitiveArray<long>(count).ToArray().Cast<object>().ToList();
                    break;
            }
        }

        public void MarshalUnion(NdrBuffer buffer)
        {
            buffer.WriteInt32LittleEndian(Values.Count);

            switch (Type)
            {
                case ClaimType.CLAIM_TYPE_STRING:
                    var arr = GetValues<string>().Select(v => v.AsMemory());

                    buffer.WriteDeferredArray(arr, val => buffer.WriteConformantVaryingArray(val.Span));
                    break;
                default:
                    buffer.WriteFixedPrimitiveArray(GetValues<long>().ToArray());
                    break;
            }
        }
    }
}
