using Microsoft.Extensions.Logging;
using System.Threading.Tasks;

namespace Kerberos.NET
{
    public class TicketReplayValidator : ITicketReplayValidator
    {
        private readonly MemoryTicketCache cache;

        public TicketReplayValidator(ILoggerFactory logger)
        {
            this.cache = new MemoryTicketCache(logger);
        }

        public async Task<bool> Add(TicketCacheEntry entry)
        {
            if (await Contains(entry))
            {
                return false;
            }

            await cache.Add(entry);

            return true;
        }

        public async Task<bool> Contains(TicketCacheEntry entry)
        {
            return await cache.Contains(entry);
        }
    }
}