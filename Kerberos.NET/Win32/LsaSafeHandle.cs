// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Runtime.InteropServices;
using static Kerberos.NET.Win32.NativeMethods;

namespace Kerberos.NET.Win32
{
    internal class LsaSafeHandle : SafeHandle
    {
        public LsaSafeHandle()
            : base(IntPtr.Zero, true)
        {
        }

        public override bool IsInvalid => this.handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            int result = LsaDeregisterLogonProcess(this.handle);

            LsaThrowIfError(result);

            this.handle = IntPtr.Zero;

            return true;
        }
    }
}
