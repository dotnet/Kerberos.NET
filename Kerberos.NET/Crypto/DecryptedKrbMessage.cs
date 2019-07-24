using Kerberos.NET.Entities;
using System;

namespace Kerberos.NET.Crypto
{
    public abstract class DecryptedKrbMessage
    {
        private Func<DateTimeOffset> nowFunc;

        [KerberosIgnore]
        public Func<DateTimeOffset> Now
        {
            get { return nowFunc ?? (nowFunc = () => DateTimeOffset.UtcNow); }
            set { nowFunc = value; }
        }

        public abstract void Validate(ValidationActions validation);

        public abstract void Decrypt(KeyTable keytab);

        protected virtual void ValidateTicketEnd(DateTimeOffset endTime, DateTimeOffset now, TimeSpan skew)
        {
            if (endTime < (now - skew))
            {
                throw new KerberosValidationException(
                    $"Token has expired. End: {endTime}; Now: {now}; Skew: {skew}"
                );
            }
        }

        protected virtual void ValidateTicketStart(DateTimeOffset startTime, DateTimeOffset now, TimeSpan skew)
        {
            if (startTime > (now + skew))
            {
                throw new KerberosValidationException(
                    $"Token Start isn't valid yet. Start: {startTime}; Now: {now}; Skew: {skew}"
                );
            }
        }

        protected virtual void ValidateRealm(string leftName, string rightName)
        {
            if (!string.Equals(leftName, rightName, StringComparison.OrdinalIgnoreCase))
            {
                throw new KerberosValidationException(
                    $"Ticket ({leftName}) and Authenticator ({rightName}) realms do not match"
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

        protected virtual void ValidateClientPrincipalIdentifier(KrbPrincipalName leftName, KrbPrincipalName rightName)
        {
            if (!leftName.Matches(rightName))
            {
                throw new KerberosValidationException(
                    "Ticket CName " +
                    $"({leftName.Type}: {leftName.Type})" +
                    " does not match Authenticator CName " +
                    $"({rightName.Type}: {rightName.Name})"
                );
            }
        }
    }
}
