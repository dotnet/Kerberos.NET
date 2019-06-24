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

        public EncryptionType EType => token?.Ticket?.EncPart?.EType ?? EncryptionType.NULL;

        public PrincipalName SName => token?.Ticket?.SName;

        public Authenticator Authenticator { get; private set; }

        public EncTicketPart Ticket { get; private set; }

        private readonly KrbApReq token;

        public override void Decrypt(KeyTable keytab)
        {
            var ciphertext = token.Ticket.EncPart.Cipher;

            var key = keytab.GetKey(EType, SName);

            var decryptedTicket = Decrypt(key, ciphertext, KeyUsage.KU_TICKET);

            Ticket = new EncTicketPart().Decode(new Asn1Element(decryptedTicket));

            var decryptedAuthenticator = Decrypt(
                new KerberosKey(Ticket.Key.RawKey),
                token.Authenticator.Cipher,
                KeyUsage.KU_AP_REQ_AUTHENTICATOR
            );

            Authenticator = new Authenticator().Decode(new Asn1Element(decryptedAuthenticator));

            var delegation = Authenticator?.Checksum?.Delegation?.DelegationTicket;

            if (delegation != null)
            {
                var decryptedDelegationTicket = Decrypt(
                    new KerberosKey(Ticket.Key.RawKey),
                    delegation.Credential.EncryptedData.Cipher,
                    KeyUsage.KU_ENC_KRB_CRED_PART
                );

                delegation.Credential.CredentialPart = 
                    new EncKrbCredPart().Decode(new Asn1Element(decryptedDelegationTicket));
            }
        }

        public virtual TimeSpan Skew { get; protected set; } = TimeSpan.FromMinutes(5);

        public override void Validate(ValidationActions validation)
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
                ValidateClientPrincipalIdentifier(Authenticator.CName, Ticket.CName);
            }

            if (validation.HasFlag(ValidationActions.Realm))
            {
                ValidateRealm(Ticket.CRealm, Authenticator.Realm);
            }

            var now = Now();

            var ctime = Authenticator.CTime.AddTicks(Authenticator.CuSec / 10);

            if (validation.HasFlag(ValidationActions.TokenWindow))
            {
                ValidateTicketSkew(now, Skew, ctime);
            }

            if (validation.HasFlag(ValidationActions.StartTime))
            {
                ValidateTicketStart(Ticket.StartTime, now, Skew);
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
