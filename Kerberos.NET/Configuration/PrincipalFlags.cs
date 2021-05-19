using System;
using System.ComponentModel;

namespace Kerberos.NET.Configuration
{
    [Flags]
    public enum PrincipalFlags
    {
        /// <summary>
        /// No flags are set.
        /// </summary>
        None = 0,

        /// <summary>
        /// Enabling this flag means that the KDC will issue tickets for this principal. Disabling this flag essentially deactivates the principal within this realm.
        /// </summary>
        [Description("allow-tickets")]
        AllowTickets = 1 << 0,

        /// <summary>
        /// Enabling this flag allows the KDC to issue user-to-user service tickets for this principal.
        /// </summary>
        [Description("dup-skey")]
        DuplicateSessionKey = 1 << 1,

        /// <summary>
        /// Enabling this flag allows the principal to obtain forwardable tickets.
        /// </summary>
        [Description("forwardable")]
        Forwardable = 1 << 2,

        /// <summary>
        /// If this flag is enabled, then the principal is required to preauthenticate using a hardware device before receiving any tickets.
        /// </summary>
        [Description("hwauth")]
        HardwareAuth = 1 << 3,

        /// <summary>
        /// Enabling this flag prevents PAC or AD-SIGNEDPATH data from being added to service tickets for the principal.
        /// </summary>
        [Description("no-auth-data-required")]
        NoAuthDataRequired = 1 << 4,

        /// <summary>
        /// If this flag is enabled, it hints the client that credentials can and should be delegated when authenticating to the service.
        /// </summary>
        [Description("ok-as-delegate")]
        OkAsDelegate = 1 << 5,

        /// <summary>
        /// Enabling this flag allows the principal to use S4USelf tickets.
        /// </summary>
        [Description("ok-to-auth-as-delegate")]
        OkToAuthAsDelegate = 1 << 6,

        /// <summary>
        /// Enabling this flag allows the principal to obtain postdateable tickets.
        /// </summary>
        [Description("postdateable")]
        Postdateable = 1 << 7,

        /// <summary>
        /// If this flag is enabled on a client principal, then that principal is required to preauthenticate to the KDC before receiving any tickets.
        /// On a service principal, enabling this flag means that service tickets for this principal will only be issued to clients with a TGT that has the preauthenticated bit set.
        /// </summary>
        [Description("preauth")]
        PreAuth = 1 << 8,

        /// <summary>
        /// Enabling this flag allows the principal to obtain proxy tickets.
        /// </summary>
        [Description("proxiable")]
        Proxiable = 1 << 9,

        /// <summary>
        /// Enabling this flag forces a password change for this principal.
        /// </summary>
        [Description("pwchange")]
        PasswordChangeRequired = 1 << 10,

        /// <summary>
        /// If this flag is enabled, it marks this principal as a password change service. This should only be used in special cases,
        /// for example, if a user’s password has expired, then the user has to get tickets for that principal without going through
        /// the normal password authentication in order to be able to change the password.
        /// </summary>
        [Description("pwservice")]
        PasswordService = 1 << 11,

        /// <summary>
        /// Enabling this flag allows the principal to obtain renewable tickets.
        /// </summary>
        [Description("renewable")]
        Renewable = 1 << 12,

        /// <summary>
        /// Enabling this flag allows the the KDC to issue service tickets for this principal.
        /// </summary>
        [Description("service")]
        Service = 1 << 13,

        /// <summary>
        /// Enabling this flag allows a principal to obtain tickets based on a ticket-granting-ticket,
        /// rather than repeating the authentication process that was used to obtain the TGT.
        /// </summary>
        [Description("tgt-based")]
        TgtBased = 14
    }
}
