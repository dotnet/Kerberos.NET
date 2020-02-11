using Kerberos.NET.Entities;

namespace Kerberos.NET
{
    /// <summary>
    /// The parameters used during a TGS-REQ
    /// </summary>
    public struct RequestServiceTicket
    {
        /// <summary>
        /// The SPN of the service a ticket is requested
        /// </summary>
        public string ServicePrincipalName { get; set; }

        /// <summary>
        /// The authentication options for this request
        /// </summary>
        public ApOptions ApOptions { get; set; }

        /// <summary>
        /// The username a service ticket is requested on-behalf-of
        /// </summary>
        public string S4uTarget { get; set; }

        /// <summary>
        /// The evidence ticket used to prove the requestor is allowed to
        /// request a ticket on-behalf-of the S4uTarget user
        /// </summary>
        public KrbTicket S4uTicket { get; set; }

        /// <summary>
        /// The TGT of the service receiving the requested ticket to initiate
        /// the U2U encrypted in session key flow
        /// </summary>
        public KrbTicket UserToUserTicket { get; set; }

        /// <summary>
        /// KDC request options
        /// </summary>
        public KdcOptions KdcOptions { get; set; }

        /// <summary>
        /// A hint provided in the TGS-REQ to help the KDC find the user details
        /// before having to decrypt their TGT
        /// </summary>
        public KrbPrincipalName CNameHint { get; set; }

        /// <summary>
        /// The realm of the authenticated user
        /// </summary>
        public string Realm { get; set; }
    }
}
