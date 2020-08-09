using System;
using System.Threading.Tasks;

namespace Kerberos.NET
{
    public interface ITicketCache
    {
        bool RefreshTickets { get; set; }

        TimeSpan RefreshInterval { get; set; }

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
