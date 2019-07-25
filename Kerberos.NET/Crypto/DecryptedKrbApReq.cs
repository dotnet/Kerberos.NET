﻿using Kerberos.NET.Entities;
using System;

namespace Kerberos.NET.Crypto
{
    public class DecryptedKrbApReq : DecryptedKrbMessage
    {
        private readonly MessageType incomingMessageType;

        public DecryptedKrbApReq(KrbApReq token, MessageType incomingMessageType = MessageType.KRB_AP_REQ)
        {
            this.token = token;
            this.incomingMessageType = incomingMessageType;
        }

        public ApOptions Options { get => token.ApOptions; }

        public EncryptionType EType => token.Ticket.EncryptedPart.EType;

        public KrbPrincipalName SName => token.Ticket.SName;

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
                EncryptedPart = KrbEncryptedData.Encrypt(
                    apRepPart.EncodeApplication(),
                    SessionKey,
                    KeyUsage.EncApRepPart
                )
            };

            return apRep;
        }

        public override void Decrypt(KeyTable keytab)
        {
            var key = keytab.GetKey(EType, SName);

            Decrypt(key);
        }

        public void Decrypt(KerberosKey key)
        {
            Ticket = token.Ticket.EncryptedPart.Decrypt(
                key,
                KeyUsage.Ticket,
                b => KrbEncTicketPart.DecodeApplication(b)
            );

            var keyUsage = KeyUsage.ApReqAuthenticator;

            if (incomingMessageType == MessageType.KRB_TGS_REQ)
            {
                keyUsage = KeyUsage.PaTgsReqAuthenticator;
            }

            Authenticator = token.Authenticator.Decrypt(
                Ticket.Key.AsKey(),
                keyUsage,
                b => KrbAuthenticator.DecodeApplication(b)
            );

            if (Authenticator.Subkey != null)
            {
                SessionKey = Authenticator.Subkey.AsKey();
            }
            else
            {
                SessionKey = Ticket.Key.AsKey();
            }

            var delegationInfo = Authenticator.Checksum?.DecodeDelegation();

            var delegation = delegationInfo?.DelegationTicket;

            if (delegation != null)
            {
                DelegationTicket = delegation.EncryptedPart.Decrypt(
                    Ticket.Key.AsKey(),
                    KeyUsage.EncKrbCredPart,
                    b => KrbEncKrbCredPart.DecodeApplication(b)
                );
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

            if (validation.HasFlag(ValidationActions.RenewTill) && Ticket.Flags.HasFlag(TicketFlags.Renewable))
            {
                ValidateTicketRenewal(Ticket.RenewTill, now, Skew);
            }
        }

        public override string ToString()
        {
            return $"{Ticket} | {Authenticator}";
        }
    }
}
