// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using Kerberos.NET.Entities;

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

        public ApOptions Options { get => this.token.ApOptions; }

        public EncryptionType EType => this.token.Ticket.EncryptedPart.EType;

        public KrbPrincipalName SName => this.token.Ticket.SName;

        public KrbAuthenticator Authenticator { get; private set; }

        public KrbEncTicketPart Ticket { get; private set; }

        public KrbEncKrbCredPart DelegationTicket { get; private set; }

        public KerberosKey SessionKey { get; private set; }

        private readonly KrbApReq token;

        public KrbApRep CreateResponseMessage()
        {
            var apRepPart = new KrbEncApRepPart
            {
                CTime = this.Authenticator.CTime,
                CuSec = this.Authenticator.CuSec,
                SequenceNumber = this.Authenticator.SequenceNumber
            };

            var apRep = new KrbApRep
            {
                EncryptedPart = KrbEncryptedData.Encrypt(
                    apRepPart.EncodeApplication(),
                    this.SessionKey,
                    KeyUsage.EncApRepPart
                )
            };

            return apRep;
        }

        public override void Decrypt(KeyTable keytab)
        {
            if (keytab == null)
            {
                throw new ArgumentNullException(nameof(keytab));
            }

            var key = keytab.GetKey(this.EType, this.SName);

            this.Decrypt(key);
        }

        public override void Decrypt(KerberosKey ticketEncryptingKey)
        {
            this.Ticket = this.token.Ticket.EncryptedPart.Decrypt(
                ticketEncryptingKey,
                KeyUsage.Ticket,
                b => KrbEncTicketPart.DecodeApplication(b)
            );

            var keyUsage = KeyUsage.ApReqAuthenticator;

            if (this.incomingMessageType == MessageType.KRB_TGS_REQ)
            {
                keyUsage = KeyUsage.PaTgsReqAuthenticator;
            }

            this.Authenticator = this.token.Authenticator.Decrypt(
                this.Ticket.Key.AsKey(),
                keyUsage,
                b => KrbAuthenticator.DecodeApplication(b)
            );

            KeyUsage? projectedUsage = null;

            if (this.Authenticator.Subkey != null)
            {
                if (keyUsage == KeyUsage.PaTgsReqAuthenticator)
                {
                    projectedUsage = KeyUsage.EncTgsRepPartSubSessionKey;
                }

                this.SessionKey = this.Authenticator.Subkey.AsKey(projectedUsage);
            }
            else
            {
                if (keyUsage == KeyUsage.PaTgsReqAuthenticator)
                {
                    projectedUsage = KeyUsage.EncTgsRepPartSessionKey;
                }

                this.SessionKey = this.Ticket.Key.AsKey(projectedUsage);
            }

            var checksum = this.Authenticator.Checksum;

            if (checksum != null)
            {
                this.DelegationTicket = this.TryExtractDelegationTicket(checksum);
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
                this.Ticket.Key.AsKey(),
                KeyUsage.EncKrbCredPart,
                b => KrbEncKrbCredPart.DecodeApplication(b)
            );
        }

        public override void Validate(ValidationActions validation)
        {
            // As defined in https://tools.ietf.org/html/rfc4120 KRB_AP_REQ verification

            if (validation.HasFlag(ValidationActions.ClientPrincipalIdentifier))
            {
                this.ValidateClientPrincipalIdentifier(this.Ticket.CName, this.Authenticator.CName);
            }

            if (validation.HasFlag(ValidationActions.Realm))
            {
                this.ValidateRealm(this.Ticket.CRealm, this.Authenticator.Realm);
            }

            var now = this.Now();

            var ctime = this.Authenticator.CTime.AddTicks(this.Authenticator.CuSec / 10);

            if (validation.HasFlag(ValidationActions.TokenWindow))
            {
                this.ValidateTicketSkew(now, this.Skew, ctime);
            }

            if (validation.HasFlag(ValidationActions.StartTime))
            {
                this.ValidateTicketStart(this.Ticket.StartTime ?? now, now, this.Skew);
            }

            if (validation.HasFlag(ValidationActions.EndTime))
            {
                this.ValidateTicketEnd(this.Ticket.EndTime, now, this.Skew);
            }

            if (validation.HasFlag(ValidationActions.RenewTill) && this.Ticket.Flags.HasFlag(TicketFlags.Renewable))
            {
                this.ValidateTicketRenewal(this.Ticket.RenewTill, now, this.Skew);
            }
        }

        public override string ToString()
        {
            return $"{this.Ticket} | {this.Authenticator}";
        }
    }
}
