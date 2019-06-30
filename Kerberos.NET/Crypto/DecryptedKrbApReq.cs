﻿using Kerberos.NET.Asn1.Entities;
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

        public EncryptionType EType => token.Ticket.Application.Value.EncryptedPart.EType;

        public KrbPrincipalName SName => token.Ticket.Application.Value.SName;

        public KrbAuthenticator Authenticator { get; private set; }

        public KrbEncTicketPart Ticket { get; private set; }

        public KrbEncKrbCredPart DelegationTicket { get; private set; }

        private readonly KrbApReq token;

        public override void Decrypt(KeyTable keytab)
        {
            var ciphertext = token.Ticket.Application.Value.EncryptedPart.Cipher;

            var key = keytab.GetKey(EType, SName);

            var decryptedTicket = Decrypt(key, ciphertext, KeyUsage.KU_TICKET);

            var ticketApp = KrbEncTicketPartApplication.Decode(decryptedTicket);

            Ticket = ticketApp.Application.Value;

            var decryptedAuthenticator = Decrypt(
                new KerberosKey(Ticket.Key.KeyValue.ToArray()),
                token.Authenticator.Cipher,
                KeyUsage.KU_AP_REQ_AUTHENTICATOR
            );

            var authenticatorApp = KrbAuthenticatorApplication.Decode(decryptedAuthenticator);

            Authenticator = authenticatorApp.Application.Value;

            var delegation = Authenticator.Checksum?.DecodeDelegation()?.DelegationTicket.Application;

            if (delegation != null)
            {
                var decryptedDelegationTicket = Decrypt(
                    new KerberosKey(Ticket.Key.KeyValue.ToArray()),
                    delegation.Value.EncryptedPart.Cipher,
                    KeyUsage.KU_ENC_KRB_CRED_PART
                );

                DelegationTicket = KrbEncKrbCredPartApplication.Decode(decryptedDelegationTicket).Application.Value;
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
