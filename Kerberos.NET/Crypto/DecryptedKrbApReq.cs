using Kerberos.NET.Entities;
using System;

namespace Kerberos.NET.Crypto
{
    public class DecryptedKrbApReq : DecryptedKrbMessage
    {
        private readonly MessageType incomingMessageType;

        public DecryptedKrbApReq(KrbApReq token, MessageType incomingMessageType = MessageType.KRB_AP_REQ)
        {
            this.token = token ?? throw new ArgumentNullException(nameof(token));

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
            var apRepPart = new KrbEncApRepPart
            {
                CTime = Authenticator.CTime,
                CuSec = Authenticator.CuSec,
                SequenceNumber = Authenticator.SequenceNumber
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

        public override void Decrypt(KerberosKey ticketEncryptingKey)
        {
            Ticket = token.Ticket.EncryptedPart.Decrypt(
                ticketEncryptingKey,
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

            KeyUsage? projectedUsage = null;

            if (Authenticator.Subkey != null)
            {
                if (keyUsage == KeyUsage.PaTgsReqAuthenticator)
                {
                    projectedUsage = KeyUsage.EncTgsRepPartSubSessionKey;
                }

                SessionKey = Authenticator.Subkey.AsKey(projectedUsage);
            }
            else
            {
                if (keyUsage == KeyUsage.PaTgsReqAuthenticator)
                {
                    projectedUsage = KeyUsage.EncTgsRepPartSessionKey;
                }

                SessionKey = Ticket.Key.AsKey(projectedUsage);
            }

            var checksum = Authenticator.Checksum;

            if (checksum != null)
            {
                DelegationTicket = TryExtractDelegationTicket(checksum);
            }
        }

        private KrbEncKrbCredPart TryExtractDelegationTicket(KrbChecksum checksum)
        {
            if (checksum.Type != KrbChecksum.ChecksumContainsDelegationType)
            {
                return null;
            }

            var delegationInfo = checksum.DecodeDelegation();

            var delegation = delegationInfo?.DelegationTicket;

            if (delegation == null)
            {
                return null;
            }

            return delegation.EncryptedPart.Decrypt(
                Ticket.Key.AsKey(),
                KeyUsage.EncKrbCredPart,
                b => KrbEncKrbCredPart.DecodeApplication(b)
            );
        }

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

            var ctime = Authenticator.CTime.AddTicks(Authenticator.CuSec / 10);

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
