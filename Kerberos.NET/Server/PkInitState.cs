// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
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
        public KrbPaPkAsReq PkInitRequest { get; set; }

        /// <summary>
        /// The decoded CMS Message prior to validating the signature.
        /// </summary>
        public SignedCms Cms { get; set; }

        /// <summary>
        /// The certificate collection presented to the KDC by the client in the CMS message.
        /// </summary>
        public X509Certificate2Collection ClientCertificate { get; } = new X509Certificate2Collection();
    }
}