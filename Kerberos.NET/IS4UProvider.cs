// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using Kerberos.NET.Client;
using System.Threading;
using System.Threading.Tasks;

namespace Kerberos.NET
{
    internal interface IS4UProvider
    {
        Task<ApplicationSessionContext> GetServiceTicket(RequestServiceTicket rst, CancellationToken cancellation);
    }
}
