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
        public string Computed { get { return GenerateKey(Container, Key); } }

        internal static string GenerateKey(string container = null, string key = null)
        {
            return $"kerberos-{container?.ToLowerInvariant()}-{key?.ToLowerInvariant()}";
        }

        public string Key { get; set; }

        public string Container { get; set; }

        public DateTimeOffset Expires { get; set; }

        public object Value { get; set; }
    }
}
