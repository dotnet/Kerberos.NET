// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using Kerberos.NET.Crypto;
using Kerberos.NET.Server;

namespace Kerberos.NET.Entities
{
    /// <summary>
    /// This structure is used to provide information to the KDC so it knows how to issue a service ticket.
    /// Note that it is a struct by design and therefore will be copied unless passed by reference.
    /// </summary>
    public struct ServiceTicketRequest : IEquatable<ServiceTicketRequest>
    {
        /// <summary>
        /// Optionally indicates which EType should be used when generating the client (session) key.
        /// If not set, the EType will be the same EType as <see cref="ServicePrincipalKey"/>.
        /// </summary>
        public EncryptionType? PreferredClientEType { get; set; }

        /// <summary>
        /// The KDC Key used to sign authorization data during ticket generation and validation
        /// </summary>
        public KerberosKey KdcAuthorizationKey { get; set; }

        /// <summary>
        /// The principal for which a service ticket is requested
        /// </summary>
        public IKerberosPrincipal Principal { get; set; }

        /// <summary>
        /// The session key that will encrypt the ticket when sent to the client
        /// </summary>
        public KerberosKey EncryptedPartKey { get; set; }

        /// <summary>
        /// Optionally specificy the EType used to encrypt the enc-part other than what is specified in <see cref="EncryptedPartKey" />
        /// </summary>
        public EncryptionType? EncryptedPartEType { get; set; }

        /// <summary>
        /// The service principal for which the ticket will be issued against
        /// </summary>
        public IKerberosPrincipal ServicePrincipal { get; set; }

        /// <summary>
        /// The key that will encrypt the ticket that only the service principal can decrypt
        /// </summary>
        public KerberosKey ServicePrincipalKey { get; set; }

        /// <summary>
        /// The flags that identify required properties of the ticket
        /// </summary>
        public TicketFlags Flags { get; set; }

        /// <summary>
        /// The client-supplied list of their known addresses. Only here for backwards compatibility
        /// and should not be relied on for any security decisions.
        /// </summary>
        public IEnumerable<KrbHostAddress> Addresses { get; set; }

        /// <summary>
        /// The name of the realm that issued the ticket.
        /// </summary>
        public string RealmName { get; set; }

        /// <summary>
        /// The current timestamp to base validation on.
        /// </summary>
        public DateTimeOffset Now { get; set; }

        /// <summary>
        /// The time at which the ticket will start being valid.
        /// </summary>
        public DateTimeOffset StartTime { get; set; }

        /// <summary>
        /// The time at which the ticket will stop being valid.
        /// </summary>
        public DateTimeOffset EndTime { get; set; }

        /// <summary>
        /// Optional. The time at which the ticket can be renewed until while it's before <see cref="StartTime"/>.
        /// </summary>
        public DateTimeOffset? RenewTill { get; set; }

        /// <summary>
        /// A unique counter for each ticket that is used to limit replay attacks.
        /// </summary>
        public int Nonce { get; set; }

        /// <summary>
        /// Indicates whether the KDC should generate or copy a PAC for this ticket.
        /// </summary>
        public bool IncludePac { get; set; }

        /// <summary>
        /// Additional authorization data to include in the encrypted portion of the ticket.
        /// </summary>
        public IEnumerable<KrbPaData> PreAuthenticationData { get; set; }

        /// <summary>
        /// SAM account name to be used to generate TGT for Windows specific user principal.
        /// If this parameter contains valid string (not empty), CName of encrypted part of ticket
        /// will be created based on provided SamAccountName.
        /// </summary>
        public string SamAccountName { get; set; }

        /// <summary>
        /// Indicates the maximum length of time a ticket can be valid regardless of what the StartTime and EndTime propeties indicate.
        /// </summary>
        public TimeSpan MaximumTicketLifetime { get; set; }

        /// <summary>
        /// Indicates the maximum length of time a valid ticket can be renewed.
        /// </summary>
        public TimeSpan MaximumRenewalWindow { get; set; }

        /// <summary>
        /// Indicates what compatibility modes if any the KDC should apply.
        /// </summary>
        public KerberosCompatibilityFlags Compatibility { get; set; }

        /// <summary>
        /// Validate the lifetime values are within spec and if not set them to be valid.
        /// </summary>
        public void ClampLifetime()
        {
            if (this.MaximumTicketLifetime <= TimeSpan.Zero)
            {
                throw new InvalidOperationException("MaximumTicketLifetime is not set");
            }

            if (this.StartTime < this.Now)
            {
                this.StartTime = this.Now;
            }

            if (this.EndTime <= DateTimeOffset.MinValue)
            {
                this.EndTime = this.StartTime + this.MaximumTicketLifetime;
            }

            if (this.StartTime >= this.EndTime ||
                (this.EndTime - this.StartTime) > this.MaximumTicketLifetime)
            {
                this.EndTime = this.StartTime + this.MaximumTicketLifetime;
            }

            if (this.Flags.HasFlag(TicketFlags.Renewable))
            {
                this.RenewTill = this.StartTime + this.MaximumRenewalWindow;
            }
        }

        public override bool Equals(object obj)
        {
            if (obj is ServiceTicketRequest srt)
            {
                return this.Equals(srt);
            }

            return false;
        }

        public bool Equals(ServiceTicketRequest other)
        {
            if (other.Addresses != this.Addresses)
            {
                return false;
            }

            if (other.EncryptedPartKey != this.EncryptedPartKey)
            {
                return false;
            }

            if (other.EndTime != this.EndTime)
            {
                return false;
            }

            if (other.Flags != this.Flags)
            {
                return false;
            }

            if (other.IncludePac != this.IncludePac)
            {
                return false;
            }

            if (other.KdcAuthorizationKey != this.KdcAuthorizationKey)
            {
                return false;
            }

            if (other.MaximumRenewalWindow != this.MaximumRenewalWindow)
            {
                return false;
            }

            if (other.MaximumTicketLifetime != this.MaximumTicketLifetime)
            {
                return false;
            }

            if (other.Nonce != this.Nonce)
            {
                return false;
            }

            if (other.Now != this.Now)
            {
                return false;
            }

            if (other.PreAuthenticationData != this.PreAuthenticationData)
            {
                return false;
            }

            if (other.PreferredClientEType != this.PreferredClientEType)
            {
                return false;
            }

            if (other.Principal != this.Principal)
            {
                return false;
            }

            if (other.RealmName != this.RealmName)
            {
                return false;
            }

            if (other.RenewTill != this.RenewTill)
            {
                return false;
            }

            if (other.SamAccountName != this.SamAccountName)
            {
                return false;
            }

            if (other.ServicePrincipal != this.ServicePrincipal)
            {
                return false;
            }

            if (other.ServicePrincipalKey != this.ServicePrincipalKey)
            {
                return false;
            }

            if (other.StartTime != this.StartTime)
            {
                return false;
            }

            if (other.Compatibility != this.Compatibility)
            {
                return false;
            }

            return true;
        }

        public override int GetHashCode()
        {
            return EntityHashCode.GetHashCode(
                this.Addresses,
                this.EncryptedPartKey,
                this.EndTime,
                this.Flags,
                this.IncludePac,
                this.KdcAuthorizationKey,
                this.MaximumRenewalWindow,
                this.MaximumTicketLifetime,
                this.Nonce,
                this.Now,
                this.PreAuthenticationData,
                this.PreferredClientEType,
                this.Principal,
                this.RealmName,
                this.RenewTill,
                this.SamAccountName,
                this.ServicePrincipal,
                this.ServicePrincipalKey,
                this.StartTime,
                this.Compatibility
            );
        }

        public static bool operator ==(ServiceTicketRequest left, ServiceTicketRequest right)
        {
            return left.Equals(right);
        }

        public static bool operator !=(ServiceTicketRequest left, ServiceTicketRequest right)
        {
            return !(left == right);
        }
    }
}
