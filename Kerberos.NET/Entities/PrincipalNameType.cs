// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

namespace Kerberos.NET.Entities
{
    /// <summary>
    /// Indicates the format of the principal name
    /// </summary>
    public enum PrincipalNameType
    {
        /// <summary>
        /// The principal name format is unknown and will be treated like <see cref="NT_PRINCIPAL" />
        /// </summary>
        NT_UNKNOWN = 0,

        /// <summary>
        /// Represents just the name of the principal and will form a name of user@realm if a realm is provided.
        /// </summary>
        NT_PRINCIPAL = 1,

        /// <summary>
        /// Represents a unique service or instance such as krbtgt and will form a name of service/name@realm.
        /// </summary>
        NT_SRV_INST = 2,

        /// <summary>
        /// Represents a service instance and will form a name of service/name@realm.
        /// </summary>
        NT_SRV_HST = 3,

        /// <summary>
        /// Represents a host as the remaining components of the name.
        /// </summary>
        NT_SRV_XHST = 4,

        /// <summary>
        /// Represents a unique identifier.
        /// </summary>
        NT_UID = 5,

        /// <summary>
        /// Represents a name encoded as X.509 Distinguished Name.
        /// </summary>
        NT_X500_PRINCIPAL = 6,

        /// <summary>
        /// represents an SMTP email name in the form of user@domain.com.
        /// </summary>
        NT_SMTP_NAME = 7,

        /// <summary>
        /// Represents an enterprise name that may be mapped by the KDC to a canonical name.
        /// </summary>
        NT_ENTERPRISE = 10,

        /// <summary>
        /// Represents a name that is considered well-known or special meaning other than identifying a particular instance.
        /// </summary>
        NT_WELLKNOWN = 11,
    }
}