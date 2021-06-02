// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;

namespace Kerberos.NET.Entities.Pac
{
    public abstract class PacObject // not NDR thing
    {
        public abstract PacType PacType { get; }

        public abstract ReadOnlyMemory<byte> Marshal();

        public abstract void Unmarshal(ReadOnlyMemory<byte> bytes);

        internal bool IsDirty { get; set; }

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
