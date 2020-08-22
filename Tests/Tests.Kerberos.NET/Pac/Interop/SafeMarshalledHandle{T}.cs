// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Runtime.InteropServices;

namespace Tests.Kerberos.NET.Pac.Interop
{
    internal class SafeMarshalledHandle<T> : SafeHandle
    {
        public T Value { get; }

        private readonly Action free;

        public SafeMarshalledHandle(T t, Action p)
            : base(IntPtr.Zero, true)
        {
            this.Value = t;
            this.free = p;
        }

        public override bool IsInvalid => false;

        protected override bool ReleaseHandle()
        {
            this.free();

            return true;
        }
    }
}