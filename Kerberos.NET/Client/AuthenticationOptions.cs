// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;

namespace Kerberos.NET.Client
{
    [Flags]
    public enum AuthenticationOptions : long
    {
        AllAuthentication = PreAuthenticate | IncludePacRequest,

        PreAuthenticate = 1L << 63,
        IncludePacRequest = 1L << 62,
        RepPartCompatible = (long)1 << 61,

        Forwardable = 1 << 30,
        Forwarded = 1 << 29,
        Proxiable = 1 << 28,
        Proxy = 1 << 27,
        AllowPostdate = 1 << 26,
        Postdated = 1 << 25,
        Renewable = 1 << 23,
        OptHardwareAuth = 1 << 20,
        ConstrainedDelegation = 1 << 17,
        Canonicalize = 1 << 16,
        RequestAnonymous = 1 << 15,
        DisableTransitCheck = 1 << 5,
        RenewableOk = 1 << 4,
        EncTktInSkey = 1 << 3,
        Renew = 1 << 1,
        Validate = 1 << 0
    }
}
