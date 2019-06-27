using System.Threading.Tasks;

namespace Kerberos.NET
{
    public class TicketReplayValidator : ITicketReplayValidator
    {
        private readonly ILogger logger;
        private readonly MemoryTicketCache cache;

        public TicketReplayValidator(ILogger logger)
        {
            this.logger = logger;

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