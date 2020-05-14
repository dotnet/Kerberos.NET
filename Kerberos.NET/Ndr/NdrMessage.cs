using Kerberos.NET.Ndr;
using System;

namespace Kerberos.NET.Entities.Pac
{
    public abstract class NdrPacObject : PacObject, INdrStruct // NDR thing
    {
        public abstract void Marshal(NdrBuffer buffer);

        public override ReadOnlySpan<byte> Marshal()
        {
            var buffer = new NdrBuffer();

            buffer.MarshalObject(this);

            return buffer.ToSpan(alignment: 8);
        }

        public abstract void Unmarshal(NdrBuffer buffer);

        public override void Unmarshal(ReadOnlyMemory<byte> bytes)
        {
            var buffer = new NdrBuffer(bytes);

            buffer.UnmarshalObject(this);
        }
    }

    public abstract class PacObject // not NDR thing
    {
        public abstract PacType PacType { get; }

        public abstract ReadOnlySpan<byte> Marshal();

        public abstract void Unmarshal(ReadOnlyMemory<byte> bytes);

        internal bool IsDirty { get; set; }

        private ReadOnlyMemory<byte> cachedEncodedValue;

        public virtual ReadOnlyMemory<byte> Encode()
        {
            if (cachedEncodedValue.Length <= 0 || IsDirty)
            {
                cachedEncodedValue = Marshal().ToArray();

                IsDirty = false;
            }

            return cachedEncodedValue;
        }
    }
}
