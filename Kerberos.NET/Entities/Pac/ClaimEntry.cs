// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using Kerberos.NET.Ndr;

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
            if (buffer == null)
            {
                throw new ArgumentNullException(nameof(buffer));
            }

            buffer.WriteDeferredConformantVaryingArray(this.Id.AsMemory());

            buffer.WriteInt16LittleEndian((short)this.Type);
            buffer.WriteInt32LittleEndian(this.Count);

            buffer.WriteDeferredStructUnion(this);
        }

        public string Id { get; private set; }

        public ClaimType Type { get; set; }

        [KerberosIgnore]
        public int Count { get; set; }

        public IList<object> Values { get; private set; } = new List<object>();

        public IEnumerable<T> GetValuesOfType<T>()
        {
            return this.Values.Select(v => (T)Convert.ChangeType(v, typeof(T), CultureInfo.InvariantCulture));
        }

        public void Unmarshal(NdrBuffer buffer)
        {
            if (buffer == null)
            {
                throw new ArgumentNullException(nameof(buffer));
            }

            buffer.ReadDeferredConformantVaryingArray<char>(v => this.Id = v.ToString());

            this.Type = (ClaimType)buffer.ReadInt16LittleEndian();
            this.Count = buffer.ReadInt32LittleEndian();

            buffer.ReadDeferredStructUnion(this);
        }

        public void UnmarshalUnion(NdrBuffer buffer)
        {
            if (buffer == null)
            {
                throw new ArgumentNullException(nameof(buffer));
            }

            this.Values = new List<object>();

            var count = buffer.ReadInt32LittleEndian();

            switch (this.Type)
            {
                case ClaimType.CLAIM_TYPE_STRING:
                    buffer.ReadDeferredArray(count, () => this.Values.Add(buffer.ReadConformantVaryingCharArray().ToString()));
                    break;
                default:
                    this.Values = buffer.ReadFixedPrimitiveArray<long>(count).ToArray().Cast<object>().ToList();
                    break;
            }
        }

        public void MarshalUnion(NdrBuffer buffer)
        {
            if (buffer == null)
            {
                throw new ArgumentNullException(nameof(buffer));
            }

            buffer.WriteInt32LittleEndian(this.Values.Count);

            switch (this.Type)
            {
                case ClaimType.CLAIM_TYPE_STRING:
                    var arr = this.GetValuesOfType<string>().Select(v => v.AsMemory());

                    buffer.WriteDeferredArray(arr, val => buffer.WriteConformantVaryingArray(val.Span));
                    break;
                default:
                    buffer.WriteFixedPrimitiveArray<long>(this.GetValuesOfType<long>().ToArray());
                    break;
            }
        }
    }
}