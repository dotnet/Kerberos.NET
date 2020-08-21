// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

namespace Kerberos.NET.Server
{
    public interface IRealmReferral
    {
        /// <summary>
        /// Returns the service principal the client should be referred to that can complete the ticket request.
        /// </summary>
        /// <returns>Returns a service principal for another realm.</returns>
        IKerberosPrincipal Refer();
    }
}