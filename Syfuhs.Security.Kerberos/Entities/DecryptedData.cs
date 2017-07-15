using Syfuhs.Security.Kerberos.Crypto;
using System;

namespace Syfuhs.Security.Kerberos.Entities
{
    public abstract class DecryptedData
    {
        public Authenticator Authenticator { get; protected set; }

        public EncTicketPart Ticket { get; protected set; }

        public static Func<DateTimeOffset> Now = () => DateTimeOffset.UtcNow;

        public abstract void Decrypt(KeyTable ketab);

        public virtual TimeSpan Skew { get; protected set; } = TimeSpan.FromMinutes(5);

        public virtual void Validate(ValidationAction validation)
        {
            // As defined in https://tools.ietf.org/html/rfc1510 A.10 KRB_AP_REQ verification

            if (Ticket == null)
            {
                throw new KerberosValidationException("Ticket is null");
            }

            if (Authenticator == null)
            {
                throw new KerberosValidationException("Authenticator is null");
            }

            if (validation.HasFlag(ValidationAction.ClientPrincipalIdentifier))
            {
                ValidateClientPrincipalIdentifier();
            }

            if (validation.HasFlag(ValidationAction.Realm))
            {
                ValidateRealm();
            }

            var now = Now();

            var ctime = Authenticator.CTime.AddTicks(Authenticator.CuSec / 10);

            if (validation.HasFlag(ValidationAction.TokenWindow))
            {
                ValidateTicketSkew(now, Skew, ctime);
            }

            if (validation.HasFlag(ValidationAction.StartTime))
            {
                ValidateTicketStart(now, Skew);
            }

            if (validation.HasFlag(ValidationAction.EndTime))
            {
                ValidateTicketEnd(now, Skew);
            }
        }

        protected virtual void ValidateTicketEnd(DateTimeOffset now, TimeSpan skew)
        {
            if (Ticket.EndTime < (now - skew))
            {
                throw new KerberosValidationException(
                    $"Token has expired. End: {Ticket.EndTime}; Now: {now}; Skew: {skew}"
                );
            }
        }

        protected virtual void ValidateTicketStart(DateTimeOffset now, TimeSpan skew)
        {
            if (Ticket.StartTime > (now + skew))
            {
                throw new KerberosValidationException(
                    $"Token Start isn't valid yet. Start: {Ticket.StartTime}; Now: {now}; Skew: {skew}"
                );
            }
        }

        protected virtual void ValidateRealm()
        {
            if (!string.Equals(Ticket.CRealm, Authenticator.Realm, StringComparison.InvariantCultureIgnoreCase))
            {
                throw new KerberosValidationException(
                    $"Ticket ({Ticket.CRealm}) and Authenticator ({Authenticator.Realm}) realms do not match"
                );
            }
        }

        protected virtual void ValidateTicketSkew(DateTimeOffset now, TimeSpan skew, DateTimeOffset ctime)
        {
            if ((now - ctime) > skew)
            {
                throw new KerberosValidationException(
                    $"Token window is greater than allowed skew. Start: {ctime}; End: {now}; Skew: {skew}"
                );
            }
        }

        protected virtual void ValidateClientPrincipalIdentifier()
        {
            if (!Ticket.CName.Equals(Authenticator.CName))
            {
                throw new KerberosValidationException(
                    "Ticket CName " +
                    $"({Ticket.CName.NameType}: {string.Join(",", Ticket.CName.Names)})" +
                    " does not match Authenticator CName " +
                    $"({Authenticator.CName.NameType}: {string.Join(",", Authenticator.CName.Names)})"
                );
            }
        }

        public override string ToString()
        {
            return $"{Ticket} | {Authenticator}";
        }
    }
}
