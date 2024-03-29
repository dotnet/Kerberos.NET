﻿// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Kerberos.NET
{
    public interface ITicketCache2 : ITicketCache
    {
        void PurgeTickets();

        Task PurgeTicketsAsync();

        IEnumerable<object> GetAll();

        Task<IEnumerable<object>> GetAllAsync();
    }

    public interface ITicketCache
    {
        bool RefreshTickets { get; set; }

        TimeSpan RefreshInterval { get; set; }

        string DefaultDomain { get; set; }

        ValueTask<bool> AddAsync(TicketCacheEntry entry);

        bool Add(TicketCacheEntry entry);

        ValueTask<bool> ContainsAsync(TicketCacheEntry entry);

        bool Contains(TicketCacheEntry entry);

        ValueTask<object> GetCacheItemAsync(string key, string container = null);

        object GetCacheItem(string key, string container = null);

        ValueTask<T> GetCacheItemAsync<T>(string key, string container = null);

        T GetCacheItem<T>(string key, string container = null);
    }
}
