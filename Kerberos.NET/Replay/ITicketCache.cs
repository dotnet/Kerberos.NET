using System.Threading.Tasks;

namespace Kerberos.NET
{
    public interface ITicketCache
    {
        Task<bool> Add(TicketCacheEntry entry);

        Task<bool> Contains(TicketCacheEntry entry);

        Task<object> Get(string v);
    }
}