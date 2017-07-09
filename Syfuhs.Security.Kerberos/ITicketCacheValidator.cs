
namespace Syfuhs.Security.Kerberos
{
    public interface ITicketCacheValidator
    {
        bool Add(string ticketIdentifier);
    }
}
