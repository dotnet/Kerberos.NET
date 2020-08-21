// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;

namespace Kerberos.NET.Entities
{
    [Flags]
    public enum KdcOptions
    {
        /// <summary>
        /// Reserved for future expansion of this field.
        /// </summary>
        Reserved = 1 << 31,

        /// <summary>
        /// The FORWARDABLE option indicates that the ticket to be issued is to
        /// have its forwardable flag set. It may only be set on the initial
        /// request, or in a subsequent request if the TGT on which it is based is
        /// also forwardable.
        /// </summary>
        Forwardable = 1 << 30,

        /// <summary>
        /// The FORWARDED option is only specified in a request to the
        /// ticket-granting server and will only be honored if the TGT in the request
        /// has its FORWARDABLE bit set. This option indicates that this is a
        /// request for forwarding. The address(es) of the host from which the resulting
        /// ticket is to be valid are included in the addresses field of the request.
        /// </summary>
        Forwarded = 1 << 29,

        /// <summary>
        /// The PROXIABLE option indicates that the ticket to be issued is to have
        /// its proxiable flag set.  It may only be set on the initial request, or a
        /// subsequent request if the TGT on which it is based is also proxiable.
        /// </summary>
        Proxiable = 1 << 28,

        /// <summary>
        /// The PROXY option indicates that this is a request for a proxy. This option
        /// will only be honored if the TGT in the request has its PROXIABLE bit set.
        /// The address(es) of the host from which the resulting ticket is to be valid
        /// are included in the addresses field of the request.
        /// </summary>
        Proxy = 1 << 27,

        /// <summary>
        /// The ALLOW-POSTDATE option indicates that the ticket to be issued is to have
        /// its MAY-POSTDATE flag set. It may only be set on the initial request, or in
        /// a subsequent request if the TGT on which it is based also has its MAY-POSTDATE
        /// flag set.
        /// </summary>
        AllowPostdate = 1 << 26,

        /// <summary>
        /// The POSTDATED option indicates that this is a request for a postdated ticket.
        /// This option will only be honored if the TGT on which it is based has its MAY-POSTDATE
        /// flag set. The resulting ticket will also have its INVALID flag set, and that flag may
        /// be reset by a subsequent request to the KDC after the starttime in the ticket has been
        /// reached.
        /// </summary>
        Postdated = 1 << 25,

        /// <summary>
        /// This option is presently unused.
        /// </summary>
        Unused7 = 1 << 24,

        /// <summary>
        /// The RENEWABLE option indicates that the ticket to be issued is to have its RENEWABLE
        /// flag set. It may only be set on the initial request, or when the TGT on which the
        /// request is based is also renewable. If this option is requested, then the rtime
        /// field in the request contains the desired absolute expiration time for the ticket.
        /// </summary>
        Renewable = 1 << 23,

        /// <summary>
        /// This option is presently unused.
        /// </summary>
        Unused9 = 1 << 22,

        /// <summary>
        /// This option is presently unused.
        /// </summary>
        Unused10 = 1 << 21,

        /// <summary>
        /// This flag was originally intended to indicate that hardware-supported authentication was
        /// used during pre-authentication. This flag is no longer recommended in the Kerberos V5 protocol.
        /// KDCs MUST NOT issue a ticket with this flag set. KDCs SHOULD NOT preserve this flag if it is
        /// set by another KDC.
        /// </summary>
        OptHardwareAuth = 1 << 20,

        /// <summary>
        /// This option is presently unused.
        /// </summary>
        Unused12 = 1 << 19,

        /// <summary>
        /// This option is presently unused.
        /// </summary>
        Unused13 = 1 << 18,

        ConstrainedDelegation = 1 << 17,

        /// <summary>
        /// In order to request referrals the Kerberos client MUST explicitly request the
        /// "canonicalize" KDC option for the AS-REQ or TGS-REQ.
        /// </summary>
        Canonicalize = 1 << 16,

        /// <summary>
        /// Indicates the client is requesting the KDC support anonymous PKINIT authentication.
        /// </summary>
        RequestAnonymous = 1 << 15,

        /// <summary>
        /// This option MUST be set in a KRB_TGS_REQ message to request Service
        /// for User to Proxy (S4U2proxy) functionality.
        /// </summary>
        CNameInAdditionalTicket = 1 << 14,

        /// <summary>
        /// This option is presently unused.
        /// </summary>
        Unused18 = 1 << 13,

        /// <summary>
        /// This option is presently unused.
        /// </summary>
        Unused19 = 1 << 12,

        /// <summary>
        /// This option is presently unused.
        /// </summary>
        Unused20 = 1 << 11,

        /// <summary>
        /// This option is presently unused.
        /// </summary>
        Unused21 = 1 << 10,

        /// <summary>
        /// This option is presently unused.
        /// </summary>
        Unused22 = 1 << 9,

        /// <summary>
        /// This option is presently unused.
        /// </summary>
        Unused23 = 1 << 8,

        /// <summary>
        /// This option is presently unused.
        /// </summary>
        Unused24 = 1 << 7,

        /// <summary>
        /// This option is presently unused.
        /// </summary>
        Unused25 = 1 << 6,

        /// <summary>
        /// By default the KDC will check the transited field of a TGT against the policy of
        /// the local realm before it will issue derivative tickets based on the TGT. If this
        /// flag is set in the request, checking of the transited field is disabled. Tickets
        /// issued without the performance of this check will be noted by the reset (0) value
        /// of the TRANSITED-POLICY-CHECKED flag, indicating to the application server that
        /// the transited field must be checked locally. KDCs are encouraged but not required
        /// to honor the DISABLE-TRANSITED-CHECK option.
        /// </summary>
        DisableTransitCheck = 1 << 5,

        /// <summary>
        /// The RENEWABLE-OK option indicates that a renewable ticket will be acceptable if a ticket
        /// with the requested life cannot otherwise be provided, in which case a renewable ticket
        /// may be issued with a renew-till equal to the requested endtime. The value of the renew-till
        /// field may still be limited by local limits, or limits selected by the individual principal
        /// or server.
        /// </summary>
        RenewableOk = 1 << 4,

        /// <summary>
        /// This option is used only by the ticket-granting service. The ENC-TKT-IN-SKEY option indicates
        /// that the ticket for the end server is to be encrypted in the session key from the additional
        /// TGT provided.
        /// </summary>
        EncTktInSkey = 1 << 3,

        /// <summary>
        /// This option is presently unused.
        /// </summary>
        Unused29 = 1 << 2,

        /// <summary>
        /// This option is used only by the ticket-granting service. The RENEW option indicates that the
        /// present request is for a renewal. The ticket provided is encrypted in the secret key for the
        /// server on which it is valid. This option will only be honored if the ticket to be renewed has
        /// its RENEWABLE flag set and if the time in its renew-till field has not passed. The ticket to
        /// be renewed is passed in the padata field as part of the authentication header.
        /// </summary>
        Renew = 1 << 1,

        /// <summary>
        /// This option is used only by the ticket-granting service. The VALIDATE option indicates that
        /// the request is to validate a postdated ticket. It will only be honored if the ticket presented
        /// is postdated, presently has its INVALID flag set, and would otherwise be usable at this time.
        /// A ticket cannot be validated before its starttime. The ticket presented for validation is
        /// encrypted in the key of the server for which it is valid and is passed in the padata field
        /// as part of the authentication header.
        /// </summary>
        Validate = 1 << 0,
    }
}