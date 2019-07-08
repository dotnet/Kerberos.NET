using Kerberos.NET.Entities;
using System;

namespace Kerberos.NET.Crypto
{
    public class DecryptedKrbApReq : DecryptedKrbMessage
    {
        public DecryptedKrbApReq(KrbApReq token, KerberosCryptoTransformer transformer)
            : base(transformer)
        {
            this.token = token;
        }

        public EncryptionType EType => token.Ticket.Application.EncryptedPart.EType;

        public KrbPrincipalName SName => token.Ticket.Application.SName;

        public KrbAuthenticator Authenticator { get; private set; }

        public KrbEncTicketPart Ticket { get; private set; }

        public KrbEncKrbCredPart DelegationTicket { get; private set; }

        public KerberosKey SessionKey { get; private set; }

        private readonly KrbApReq token;

        public KrbApRep CreateResponseMessage()
        {
            KerberosConstants.Now(out DateTimeOffset ctime, out int usec);

            var apRepPart = new KrbEncApRepPart
            {
                CTime = ctime,
                CuSec = usec
            };

            var apRep = new KrbApRep
            {
                EncryptedPart = KrbEncryptedData.Encrypt(apRepPart.EncodeAsApplication(), SessionKey, KeyUsage.EncApRepPart)
            };

            return apRep;
        }

        public override void Decrypt(KeyTable keytab)
        {
            var ciphertext = token.Ticket.Application.EncryptedPart.Cipher;

            var key = keytab.GetKey(EType, SName);

            var decryptedTicket = Decrypt(key, ciphertext, KeyUsage.Ticket);

            var ticketApp = KrbEncTicketPartApplication.Decode(decryptedTicket);

            Ticket = ticketApp.Application;

            var decryptedAuthenticator = Decrypt(
                Ticket.Key.AsKey(),
                token.Authenticator.Cipher,
                KeyUsage.ApReqAuthenticator
            );

            var authenticatorApp = KrbAuthenticatorApplication.Decode(decryptedAuthenticator);

            Authenticator = authenticatorApp.Application;

            SessionKey = Authenticator.Subkey.AsKey();

            var delegationInfo = Authenticator.Checksum?.DecodeDelegation();

            var delegation = delegationInfo?.DelegationTicket?.Application;

            if (delegation != null)
            {
                var decryptedDelegationTicket = Decrypt(
                    Ticket.Key.AsKey(),
                    delegation.EncryptedPart.Cipher,
                    KeyUsage.EncKrbCredPart
                );

                DelegationTicket = KrbEncKrbCredPartApplication.Decode(decryptedDelegationTicket).Application;
            }
        }

        public virtual TimeSpan Skew { get; protected set; } = TimeSpan.FromMinutes(5);

        public override void Validate(ValidationActions validation)
        {
            // As defined in https://tools.ietf.org/html/rfc4120 KRB_AP_REQ verification

            if (validation.HasFlag(ValidationActions.ClientPrincipalIdentifier))
            {
                ValidateClientPrincipalIdentifier(Authenticator.CName, Ticket.CName);
            }

            if (validation.HasFlag(ValidationActions.Realm))
            {
                ValidateRealm(Ticket.CRealm, Authenticator.Realm);
            }

            var now = Now();

            var ctime = Authenticator.CTime.AddTicks(Authenticator.Cusec / 10);

            if (validation.HasFlag(ValidationActions.TokenWindow))
            {
                ValidateTicketSkew(now, Skew, ctime);
            }

            if (validation.HasFlag(ValidationActions.StartTime))
            {
                ValidateTicketStart(Ticket.StartTime ?? now, now, Skew);
            }

            if (validation.HasFlag(ValidationActions.EndTime))
            {
                ValidateTicketEnd(Ticket.EndTime, now, Skew);
            }
        }

        public override string ToString()
        {
            return $"{Ticket} | {Authenticator}";
        }
    }
}
