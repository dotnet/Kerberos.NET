using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;

namespace Kerberos.NET.Server
{
    /// <summary>
    /// Contains the state information of a PK-INIT request used between 
    /// the pre-validation and validation phases of the request.
    /// </summary>
    public class PkInitState : PaDataState
    {
        /// <summary>
        /// The decoded PK-INIT request message.
        /// </summary>
        public KrbPaPkAsReq PkInitRequest { get; internal set; }

        /// <summary>
        /// The decoded CMS Message prior to validating the signature.
        /// </summary>
        public SignedCms Cms { get; internal set; }

        /// <summary>
        /// The certificate collection presented to the KDC by the client in the CMS message.
        /// </summary>
        public X509Certificate2Collection ClientCertificate { get; internal set; }
    }

    public class TgsState : PaDataState
    {
        /// <summary>
        /// the AP-REQ representing the ticket-granting-ticket in the PA-Data
        /// </summary>
        public KrbApReq ApReq { get; set; }
        public DecryptedKrbApReq DecryptedApReq { get; internal set; }
    }

    /// <summary>
    /// An abstract hole for storing state of pre-auth processes
    /// </summary>
    public abstract class PaDataState
    {
    }
}