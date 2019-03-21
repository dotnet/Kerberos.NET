using Kerberos.NET.Entities;
using System;

namespace Kerberos.NET.Crypto
{
    public abstract class DecryptedData
    {
        public abstract EncryptionType EType { get; }

        public Authenticator Authenticator { get; protected set; }

        public EncTicketPart Ticket { get; protected set; }

        public PrincipalName SName { get; protected set; }

        private Func<DateTimeOffset> nowFunc;

        [KerberosIgnore]
        public Func<DateTimeOffset> Now
        {
            get { return nowFunc ?? (nowFunc = () => DateTimeOffset.UtcNow); }
            set { nowFunc = value; }
        }

        public abstract void Decrypt(KeyTable keytab);

        public virtual TimeSpan Skew { get; protected set; } = TimeSpan.FromMinutes(5);

        public virtual void Validate(ValidationActions validation)
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

            if (validation.HasFlag(ValidationActions.ClientPrincipalIdentifier))
            {
                ValidateClientPrincipalIdentifier();
            }

            if (validation.HasFlag(ValidationActions.Realm))
            {
                ValidateRealm();
            }

            var now = Now();

            var ctime = Authenticator.CTime.AddTicks(Authenticator.CuSec / 10);

            if (validation.HasFlag(ValidationActions.TokenWindow))
            {
                ValidateTicketSkew(now, Skew, ctime);
            }

            if (validation.HasFlag(ValidationActions.StartTime))
            {
                ValidateTicketStart(now, Skew);
            }

            if (validation.HasFlag(ValidationActions.EndTime))
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
            if (!string.Equals(Ticket.CRealm, Authenticator.Realm, StringComparison.OrdinalIgnoreCase))
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
            if (!Ticket.CName.Matches(Authenticator.CName))
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
