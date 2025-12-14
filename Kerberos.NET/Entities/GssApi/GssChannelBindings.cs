// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;

namespace Kerberos.NET.Entities.GssApi
{
    /// <summary>
    /// Represents GSS-API channel bindings.
    /// </summary>
    public class GssChannelBindings
    {
        /// <summary>
        /// Gets or sets the initiator address type.
        /// </summary>
        public uint InitiatorAddrType { get; set; }

        /// <summary>
        /// Gets or sets the initiator address.
        /// </summary>
        public ReadOnlyMemory<byte> InitiatorAddress { get; set; }

        /// <summary>
        /// Gets or sets the acceptor address type.
        /// </summary>
        public uint AcceptorAddrType { get; set; }

        /// <summary>
        /// Gets or sets the acceptor address.
        /// </summary>
        public ReadOnlyMemory<byte> AcceptorAddress { get; set; }

        /// <summary>
        /// Gets or sets the application data.
        /// </summary>
        public ReadOnlyMemory<byte> ApplicationData { get; set; }

        /// <summary>
        /// Represents no channel bindings.
        /// </summary>
        public static readonly GssChannelBindings GSS_C_NO_CHANNEL_BINDINGS = null;
    }
}
