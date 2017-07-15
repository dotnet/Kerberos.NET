using System;

namespace Syfuhs.Security.Kerberos
{
    public interface ITicketReplayValidator
    {
        bool Add(TicketCacheEntry entry);

        bool Contains(TicketCacheEntry entry);
    }

    public class TicketCacheEntry
    {
        public string Key { get; set; }

        public string Container { get; set; }

        public DateTimeOffset Expires { get; set; }
    }
}
