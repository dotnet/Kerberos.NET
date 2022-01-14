// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System.Threading.Tasks;

namespace Kerberos.NET
{
    public interface ITicketReplayValidator
    {
        Task<bool> Add(TicketCacheEntry entry);

        Task<bool> Contains(TicketCacheEntry entry);
    }
}
