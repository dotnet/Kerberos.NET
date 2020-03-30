using Kerberos.NET.Crypto;
using Kerberos.NET.Server;
using System;
using System.Collections.Generic;

namespace Kerberos.NET.Entities
{
    /// <summary>
    /// This structure is used to provide information to the KDC so it knows how to issue a service ticket.
    /// Note that it is a struct by design and therefore will be copied unless passed by reference.
    /// </summary>
    public struct ServiceTicketRequest
    {
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
    }
}
