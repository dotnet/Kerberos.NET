// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

namespace Kerberos.NET.Server
{
    public enum PrincipalType
    {
        /// <summary>
        /// Indicates the principal is a regular user that can authenticate and request service tickets
        /// </summary>
        User = 0,

        /// <summary>
        /// Indicates the principal is a service that can receive service tickets from other users
        /// </summary>
        Service,

        /// <summary>
        /// Indicates the principal is actually a partner realm and needs to be referred before the request can be completed
        /// </summary>
        TrustedDomain
    }
}