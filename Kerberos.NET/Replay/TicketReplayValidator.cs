using Microsoft.Extensions.Logging;
using System.Threading.Tasks;

namespace Kerberos.NET
{
    public class TicketReplayValidator : ITicketReplayValidator
    {
        private readonly MemoryTicketCache cache;

        public TicketReplayValidator(ILoggerFactory logger)
        {
            this.cache = new MemoryTicketCache(logger) { BlockUpdates = true };
        }

        public async Task<bool> Add(TicketCacheEntry entry)
        {
            return await cache.AddAsync(entry);
        }

        public async Task<bool> Contains(TicketCacheEntry entry)
        {
            var got = await cache.GetCacheItemAsync(entry.Key);

            return got != null;
        }
    }
}
