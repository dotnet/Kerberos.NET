// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.ComponentModel;

namespace Kerberos.NET.Client
{
    [Flags]
    public enum AuthenticationOptions : long
    {
        AllAuthentication = PreAuthenticate | IncludePacRequest,

        [Description("Pre-authenticate")]
        PreAuthenticate = 1L << 63,

        [Description("Include PAC")]
        IncludePacRequest = 1L << 62,

        [Description("Rep-Part Compatible")]
        RepPartCompatible = 1L << 61,

        Forwardable = 1 << 30,
        Forwarded = 1 << 29,
        Proxiable = 1 << 28,
        Proxy = 1 << 27,

        [Description("Allow Postdate")]
        AllowPostdate = 1 << 26,
        Postdated = 1 << 25,
        Renewable = 1 << 23,

        [Description("Optional Hardware Auth")]
        OptHardwareAuth = 1 << 20,

        [Description("Constrained Delegation")]
        ConstrainedDelegation = 1 << 17,
        Canonicalize = 1 << 16,

        [Description("Request Anonymous")]
        RequestAnonymous = 1 << 15,

        [Description("Disable Transit Check")]
        DisableTransitCheck = 1 << 5,

        [Description("Renewable OK")]
        RenewableOk = 1 << 4,

        [Description("Encrypt Ticket in Session Key")]
        EncTktInSkey = 1 << 3,
        Renew = 1 << 1,
        Validate = 1 << 0
    }
}
