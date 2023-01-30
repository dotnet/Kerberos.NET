// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;

namespace Kerberos.NET.Entities.Pac
{
    internal sealed class UnknownPacObject : PacObject
    {
        public UnknownPacObject(PacType type, ReadOnlyMemory<byte> blob)
        {
            this.PacType = type;
            this.Blob = blob;
        }

        public override PacType PacType { get; }

        public ReadOnlyMemory<byte> Blob { get; private set; }

        public override ReadOnlyMemory<byte> Marshal()
        {
            return this.Blob;
        }

        public override void Unmarshal(ReadOnlyMemory<byte> bytes)
        {
            this.Blob = bytes;
        }
    }

    public abstract class PacObject // not NDR thing
    {
        public abstract PacType PacType { get; }

        public abstract ReadOnlyMemory<byte> Marshal();

        public abstract void Unmarshal(ReadOnlyMemory<byte> bytes);

        internal bool IsDirty { get; set; }

        internal long Offset { get; set; }

        private ReadOnlyMemory<byte> cachedEncodedValue;

        public virtual ReadOnlyMemory<byte> Encode()
        {
            if (this.cachedEncodedValue.Length <= 0 || this.IsDirty)
            {
                this.cachedEncodedValue = this.Marshal();

                this.IsDirty = false;
            }

            return this.cachedEncodedValue;
        }
    }
}
