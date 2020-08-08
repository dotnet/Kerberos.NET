using System;
using System.Threading.Tasks;

namespace Kerberos.NET
{
    public interface ITicketCache
    {
        bool RefreshTickets { get; set; }

        TimeSpan RefreshInterval { get; set; }

        Task<bool> AddAsync(TicketCacheEntry entry);

        bool Add(TicketCacheEntry entry);

        Task<bool> ContainsAsync(TicketCacheEntry entry);

        bool Contains(TicketCacheEntry entry);

        Task<object> GetCacheItemAsync(string key, string container = null);

        object GetCacheItem(string key, string container = null);

        Task<T> GetCacheItemAsync<T>(string key, string container = null);

        T GetCacheItem<T>(string key, string container = null);
    }
}
