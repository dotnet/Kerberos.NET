// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.ComponentModel;

namespace Kerberos.NET.Entities
{
    [Flags]
    public enum TicketFlags
    {
        /// <summary>
        /// Reserved. Indicates the absense of flags.
        /// </summary>
        None = -1,

        /// <summary>
        /// Reserved for future extension.
        /// </summary>
        Reserved = 1 << 31,

        /// <summary>
        /// Tells the ticket-granting service that it can issue a new TGT—based on the
        /// presented TGT—with a different network address based on the presented TGT.
        /// </summary>
        Forwardable = 1 << 30,

        /// <summary>
        /// Indicates either that a TGT has been forwarded or that a ticket was issued from a forwarded TGT.
        /// </summary>
        Forwarded = 1 << 29,

        /// <summary>
        /// Tells the ticket-granting service that it can issue tickets with a network address that
        /// differs from the one in the TGT.
        /// </summary>
        Proxiable = 1 << 28,

        /// <summary>
        /// Indicates that the network address in the ticket is different from the one in the TGT
        /// used to obtain the ticket.
        /// </summary>
        Proxy = 1 << 27,

        /// <summary>
        /// Indicates the requested ticket may be post-dated for use in future.
        /// </summary>
        [Description("May Post-date")]
        MayPostDate = 1 << 26,

        /// <summary>
        /// Indicates the requested ticket is post-dated for use in the future.
        /// </summary>
        [Description("Post-dated")]
        PostDated = 1 << 25,

        /// <summary>
        /// This flag indicates that a ticket is invalid, and it must be validated by the KDC before use.
        /// Application servers must reject tickets which have this flag set.
        /// </summary>
        Invalid = 1 << 24,

        /// <summary>
        /// Used in combination with the End Time and Renew Till fields to cause tickets with long life
        /// spans to be renewed at the KDC periodically.
        /// </summary>
        Renewable = 1 << 23,

        /// <summary>
        /// Indicates that a ticket was issued using the authentication service (AS) exchange and
        /// not issued based on a TGT.
        /// </summary>
        Initial = 1 << 22,

        /// <summary>
        /// Indicates that the client was authenticated by the KDC before a ticket was issued.
        /// This flag usually indicates the presence of an authenticator in the ticket.
        /// It can also flag the presence of credentials taken from a smart card logon.
        /// </summary>
        [Description("Pre-authenticated")]
        PreAuthenticated = 1 << 21,

        /// <summary>
        /// This flag was originally intended to indicate that hardware-supported authentication
        /// was used during pre-authentication. This flag is no longer recommended in the Kerberos
        /// V5 protocol. KDCs MUST NOT issue a ticket with this flag set. KDCs SHOULD NOT preserve
        /// this flag if it is set by another KDC.
        /// </summary>
        [Description("Hardware Authenticated")]
        HardwareAuthentication = 1 << 20,

        /// <summary>
        /// Application servers MUST ignore the TRANSITED-POLICY-CHECKED flag.
        /// </summary>
        [Description("Transit Policy-Checked")]
        TransitPolicyChecked = 1 << 19,

        /// <summary>
        /// The KDC MUST set the OK-AS-DELEGATE flag if the service account is trusted for delegation.
        /// </summary>
        [Description("Ok-as-delegate")]
        OkAsDelegate = 1 << 18,

        /// <summary>
        /// Indicates the client supports FAST negotiation.
        /// </summary>
        [Description("Encrypted Pre-authentication")]
        EncryptedPreAuthentication = 1 << 16,

        /// <summary>
        /// Indicates the ticket is anonymous.
        /// </summary>
        Anonymous = 1 << 15
    }
}
