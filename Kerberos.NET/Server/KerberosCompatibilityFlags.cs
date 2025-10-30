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

        /// <summary>
        /// Do not copy the name from the TGT if the canonicalize bit is set
        /// </summary>
        DoNotCanonicalizeTgsReqFromTgt = 1 << 1,

        /// <summary>
        /// Realms are unique between the client and the target but historically they shared common
        /// fields or properties. This separates the names into two.
        /// </summary>
        IsolateRealmsConsistently = 1 << 2,

        /// <summary>
        /// CName handling was historically non-spec compliant in some cases.
        /// This flag enables handling that more strictly adheres to the spec, for better compliance
        /// with other implementations.
        /// </summary>
        EnableSpecCompliantCNameHandling = 1 << 3,
    }
}
