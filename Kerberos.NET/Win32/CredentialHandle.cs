// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Runtime.InteropServices;

namespace Kerberos.NET.Win32
{
    public class CredentialHandle : SafeHandle
    {
        public unsafe CredentialHandle(void* cred)
            : base(new IntPtr(cred), true)
        {
        }

        public override bool IsInvalid => this.handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            return true;
        }
    }
}