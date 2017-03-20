using System;
using System.Security;

namespace Syfuhs.Security.Kerberos.Entities
{
    public abstract class DecryptedData
    {
        public Authenticator Authenticator { get; protected set; }

        public EncTicketPart Ticket { get; protected set; }

        public static Func<DateTimeOffset> Now = () => DateTimeOffset.UtcNow;

        public abstract void Decrypt();

        public virtual void Validate()
        {
            // As defined in https://tools.ietf.org/html/rfc1510 A.10 KRB_AP_REQ verification

            if (Ticket == null)
            {
                throw new SecurityException("Ticket is null");
            }

            if (Authenticator == null)
            {
                throw new SecurityException("Authenticator is null");
            }

            if (!Ticket.CName.Equals(Authenticator.CName))
            {
                throw new SecurityException(
                    "Ticket CName " +
                    $"({Ticket.CName.NameType}: {string.Join(",", Ticket.CName.Names)})" +
                    " does not match Authenticator CName " +
                    $"({Authenticator.CName.NameType}: {string.Join(",", Authenticator.CName.Names)})"
                );
            }

            if (!string.Equals(Ticket.CRealm, Authenticator.Realm, StringComparison.InvariantCultureIgnoreCase))
            {
                throw new SecurityException($"Ticket ({Ticket.CRealm}) and Authenticator ({Authenticator.Realm}) realms do not match");
            }

            var now = Now();

            var skew = TimeSpan.FromMinutes(5);

            var ctime = Authenticator.CTime.AddTicks(Authenticator.CuSec / 10);

            if ((now - ctime) > skew)
            {
                throw new SecurityException($"Token window is greater than allowed skew. Start: {ctime}; End: {now}; Skew: {skew}");
            }

            if (Ticket.StartTime > (now + skew))
            {
                throw new SecurityException($"Token Start isn't valid yet. Start: {Ticket.StartTime}; Now: {now}; Skew: {skew}");
            }

            if (Ticket.EndTime < (now - skew))
            {
                throw new SecurityException($"Token has expired. End: {Ticket.EndTime}; Now: {now}; Skew: {skew}");
            }
        }

        public override string ToString()
        {
            return $"{Ticket} | {Authenticator}";
        }
    }
}
