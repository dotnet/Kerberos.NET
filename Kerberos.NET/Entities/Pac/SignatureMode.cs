// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

namespace Kerberos.NET.Entities
{
    /// <summary>
    /// Defines how the PAC signatures should be processed.
    /// </summary>
    public enum SignatureMode
    {
        /// <summary>
        /// Indicates the Server Signature should be verified.
        /// </summary>
        Server = 1 << 0,

        /// <summary>
        /// Indicates the KDC Signature should be verified. This requries the Server signature to also be verified.
        /// </summary>
        Kdc = Server | 1 << 1
    }
}