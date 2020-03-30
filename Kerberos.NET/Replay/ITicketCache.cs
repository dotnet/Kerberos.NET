using System;
using System.Threading.Tasks;

namespace Kerberos.NET
{
    public interface ITicketCache
    {
        bool RefreshTickets { get; set; }

        TimeSpan RefreshInterval { get; set; }

        Task<bool> Add(TicketCacheEntry entry);

        Task<bool> Contains(TicketCacheEntry entry);

        Task<object> Get(string key, string container = null);

        Task<T> Get<T>(string key, string container = null);
    }
}
