// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
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

        public KrbTicket EncryptedTicket => this.token.Ticket;

        public KrbEncTicketPart Ticket { get; private set; }

        public KrbEncKrbCredPart DelegationTicket { get; private set; }

        /// <summary>
        /// The channel binding hash (Bnd field) extracted from the authenticator checksum,
        /// as described in RFC 4121 section 4.1.1.2. This is a 16-byte MD5 hash of the
        /// <see cref="GssChannelBindings"/> structure. Will be null or empty if no channel
        /// bindings were supplied by the initiator.
        /// </summary>
        public ReadOnlyMemory<byte> ChannelBindingHash { get; private set; }

        /// <summary>
        /// Expected channel bindings to validate against when <see cref="ValidationActions.ChannelBinding"/> is enabled.
        /// </summary>
        public GssChannelBindings ExpectedChannelBindings { get; set; }

        /// <summary>
        /// Accepts a raw SEC_CHANNEL_BINDINGS buffer (as returned by Windows SSPI)
        /// and converts it to <see cref="ExpectedChannelBindings"/>.
        /// </summary>
        public void SetExpectedChannelBindingsFromSecChannelBindings(ReadOnlyMemory<byte> buffer)
        {
            this.ExpectedChannelBindings = GssChannelBindings.FromSecChannelBindings(buffer);
        }

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

            var keys = keytab.GetKeys(this.EType, this.SName);

            if (!keys.Any())
            {
                throw new InvalidOperationException($"Could not find a key for {this.EType} and {this.SName.FullyQualifiedName}");
            }

            Exception ex = null;

            foreach (var key in keys)
            {
                try
                {
                    this.Decrypt(key);
                    return;
                }
                catch (CryptographicException cex)
                {
                    ex = cex;
                    continue;
                }
                catch (SecurityException secx)
                {
                    ex = secx;
                    continue;
                }
            }

            if (ex != null)
            {
                throw ex;
            }
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

            if (delegationInfo != null)
            {
                this.ChannelBindingHash = delegationInfo.ChannelBindingHash;
            }

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
                this.ValidateRealm(this.Ticket.CRealm, this.Authenticator.CRealm);
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

            if (validation.HasFlag(ValidationActions.ChannelBinding))
            {
                this.ValidateChannelBinding();
            }
        }

        protected virtual void ValidateChannelBinding()
        {
            if (this.ExpectedChannelBindings == null)
            {
                return;
            }

            var expectedHash = this.ExpectedChannelBindings.ComputeBindingHash();

            if (this.ChannelBindingHash.Length == 0)
            {
                throw new KerberosValidationException(
                    "Channel Bindings are required by the acceptor but were not supplied by the initiator."
                );
            }

            if (!KerberosCryptoTransformer.AreEqualSlow(expectedHash.Span, this.ChannelBindingHash.Span))
            {
                throw new KerberosValidationException(
                    "The Channel Bindings hash from the initiator does not match the expected channel bindings."
                );
            }
        }

        public override string ToString()
        {
            return $"{this.Ticket} | {this.Authenticator}";
        }
    }
}
