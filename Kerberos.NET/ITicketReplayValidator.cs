using System;
using System.Threading.Tasks;

namespace Kerberos.NET
{
    public interface ITicketReplayValidator
    {
        Task<bool> Add(TicketCacheEntry entry);

        Task<bool> Contains(TicketCacheEntry entry);
    }

    public class TicketCacheEntry
    {
        public string Computed { get { return $"kerberos-{Container}-{Key}"; } }

        public string Key { get; set; }

        public string Container { get; set; }

        public DateTimeOffset Expires { get; set; }
    }
}
