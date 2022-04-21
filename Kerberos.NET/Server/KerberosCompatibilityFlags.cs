// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;

namespace Kerberos.NET.Server
{
    /// <summary>
    /// Identifies which compatibility shims should be enforced by the KDC.
    /// </summary>
    [Flags]
    public enum KerberosCompatibilityFlags
    {
        /// <summary>
        /// Do not enforce any compatibility shims.
        /// </summary>
        None = 0,

        /// <summary>
        /// Always uppercase realm names.
        /// </summary>
        NormalizeRealmsUppercase = 1 << 0,
    }
}
