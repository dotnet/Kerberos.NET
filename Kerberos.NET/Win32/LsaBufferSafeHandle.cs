// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Runtime.InteropServices;
using static Kerberos.NET.Win32.NativeMethods;

namespace Kerberos.NET.Win32
{
    internal class LsaBufferSafeHandle : SafeHandle
    {
        public LsaBufferSafeHandle()
            : base(IntPtr.Zero, true)
        {
        }

        public override bool IsInvalid => this.handle == IntPtr.Zero;

        public int BufferLength { get; set; }

        public unsafe void* GetVoid()
        {
            return (void*)this.DangerousGetHandle();
        }

        public unsafe Span<byte> AsSpan() => new(this.GetVoid(), this.BufferLength);

        protected override bool ReleaseHandle()
        {
            var result = LsaFreeReturnBuffer(this.handle);

            LsaThrowIfError(result);

            this.handle = IntPtr.Zero;

            return true;
        }
    }
}
