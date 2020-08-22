// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;

namespace Kerberos.NET.Server
{
    /// <summary>
    /// PreAuthenticationContext contains the state of the request
    /// as it moves through KDC request handler pipelines
    /// </summary>
    public class PreAuthenticationContext
    {
        /// <summary>
        /// The message that is currently processed by the handler.
        /// </summary>
        public IKerberosMessage Message { get; set; }

        /// <summary>
        /// The identity that provides evidence the client is authenticated.
        /// In this case it should always be krbtgt or or a referral realm service.
        /// </summary>
        public IKerberosPrincipal EvidenceTicketIdentity { get; set; }

        /// <summary>
        /// The key used to validate the evidence ticket is valid.
        /// </summary>
        public KerberosKey EvidenceTicketKey { get; set; }

        /// <summary>
        /// The identity that will be the subject of the issued ticket.
        /// </summary>
        public IKerberosPrincipal Principal { get; set; }

        /// <summary>
        /// The identity that will be the target of the issued ticket.
        /// </summary>
        public IKerberosPrincipal ServicePrincipal { get; set; }

        /// <summary>
        /// The session key used to protect tickets as they're returned to the client.
        /// </summary>
        public KerberosKey EncryptedPartKey { get; set; }

        /// <summary>
        /// Indicates whether the handler has decided if it has enough information
        /// to proceed with issuing a ticket to the requested service.
        /// </summary>
        public bool PreAuthenticationSatisfied => this.EncryptedPartKey != null;

        /// <summary>
        /// Additional pre-auth data that should be included in the response.
        /// </summary>
        public IEnumerable<KrbPaData> PaData { get; set; }

        /// <summary>
        /// The ticket containing the principal identity protected by the evidence ticket.
        /// </summary>
        public KrbEncTicketPart Ticket { get; set; }

        /// <summary>
        /// A failure if any that was raised by the KDC handler pipeline. It should not be ignored.
        /// </summary>
        public Exception Failure { get; set; }

        /// <summary>
        /// The active state of preauthentication handlers
        /// </summary>
        public IDictionary<PaDataType, PaDataState> PreAuthenticationState { get; } = new Dictionary<PaDataType, PaDataState>();

        /// <summary>
        /// The PA-Data type that authenticated the client.
        /// </summary>
        public PaDataType ClientAuthority { get; set; } = PaDataType.PA_NONE;

        /// <summary>
        /// Indicates whether the requested service ticket should include a PAC.
        /// The null, the handler will detect if a PAC is required based on whether
        /// the PA-Data includes the KrbPaPacRequest or the evidence ticket includes a PAC.
        /// </summary>
        public bool? IncludePac { get; set; }

        /// <summary>
        /// Retrieve the current pre-authentication state for a particular PA-Data type.
        /// If the initial state is not present it will be created.
        /// </summary>
        /// <typeparam name="T">The expected type of the returned state instance.</typeparam>
        /// <param name="type">The PA-Data type the state belongs to.</param>
        /// <returns>Returns the current state of the pre-authentication type.</returns>
        public T GetState<T>(PaDataType type)
            where T : PaDataState, new()
        {
            if (!this.PreAuthenticationState.TryGetValue(type, out PaDataState val))
            {
                val = new T();

                this.PreAuthenticationState[type] = val;
            }

            return (T)val;
        }
    }
}