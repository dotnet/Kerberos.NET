// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;

namespace Kerberos.NET.Entities
{
    /// <summary>
    /// Indicates what options of the PAC are requested and supported from the KDC.
    /// </summary>
    [Flags]
    public enum PacOptions
    {
        /// <summary>
        /// Indicates the client can support claims issued by the KDC.
        /// </summary>
        Claims = 1 << 31,

        /// <summary>
        /// Indicates the client is aware of Read-Only Domain Controllers and handles RODC-specific errors.
        /// </summary>
        BranchAware = 1 << 30,

        /// <summary>
        /// Indicates to the KDC that the requested message was re-sent to a full KDC
        /// because the original RODC could not fulfill the request appropriately.
        /// </summary>
        ForwardToFullDc = 1 << 29,

        /// <summary>
        /// Indicates the client can support resource-based constrained delegation.
        /// </summary>
        ResourceBasedConstrainedDelegation = 1 << 28
    }
}