using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using System;
using System.Collections.Generic;

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
        public bool PreAuthenticationSatisfied => EncryptedPartKey != null;

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

        public T GetState<T>(PaDataType type)
            where T : PaDataState, new()
        {
            if (!PreAuthenticationState.TryGetValue(type, out PaDataState val))
            {
                val = new T();

                PreAuthenticationState[type] = val;
            }

            return (T)val;
        }

        /// <summary>
        /// The PA-Data type that authenticated the client.
        /// </summary>
        public PaDataType ClientAuthority { get; set; } = PaDataType.PA_NONE;
    }
}