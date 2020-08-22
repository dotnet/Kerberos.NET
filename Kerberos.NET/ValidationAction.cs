// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;

namespace Kerberos.NET
{
    /// <summary>
    /// Indicates how an AP-REQ should be validated by the receiving service.
    /// </summary>
    [Flags]
    public enum ValidationActions
    {
        /// <summary>
        /// DANGER: Indicates that the AP-REQ should not be validated at all.
        /// </summary>
        None = 0,

        /// <summary>
        /// Indicates that the CName in the Authenticator matches the CName in the Ticket.
        /// </summary>
        ClientPrincipalIdentifier = 1 << 0,

        /// <summary>
        /// Indicates that the Realm in the authenticator matches the Realm in the Ticket.
        /// </summary>
        Realm = 1 << 1,

        /// <summary>
        /// Indicates the authentication instant must occur recently within a given skew (often 5 minutes or less).
        /// </summary>
        TokenWindow = 1 << 2,

        /// <summary>
        /// Indicates the ticket must be issued before the time of validation (now).
        /// </summary>
        StartTime = 1 << 3,

        /// <summary>
        /// Indicates the ticket must not already be expired at the time of validation (now).
        /// </summary>
        EndTime = 1 << 4,

        /// <summary>
        /// Indicates the AP-REQ must not be replayed.
        /// </summary>
        Replay = 1 << 5,

        /// <summary>
        /// Indicates the PAC within the Ticket must have a valid signature signed using the service key.
        /// </summary>
        Pac = 1 << 6,

        /// <summary>
        /// Indicates the Ticket renewal period if set must be before the time of validation (now).
        /// </summary>
        RenewTill = 1 << 7,

        /// <summary>
        /// Indicates all validation actions must be invoked.
        /// </summary>
        All = ClientPrincipalIdentifier | Realm | TokenWindow | StartTime | EndTime | Replay | Pac | RenewTill
    }
}