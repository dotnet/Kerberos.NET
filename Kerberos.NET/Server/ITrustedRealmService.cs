// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using Kerberos.NET.Entities;

namespace Kerberos.NET.Server
{
    public interface ITrustedRealmService
    {
        /// <summary>
        /// Examines the TGS-REQ and determines if the request can be fulfilled by another trusted realm. A referral
        /// is issued if the request can be fulfilled by another trusted realm.
        /// </summary>
        /// <param name="tgsReq">The TGS-REQ message to examine.</param>
        /// <param name="context">The current authentication context of the request.</param>
        /// <returns>Returns a referral if another realm can fulfill the request otherwise it returns null.</returns>
        IRealmReferral ProposeTransit(KrbTgsReq tgsReq, PreAuthenticationContext context);
    }
}