// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;

namespace Kerberos.NET.Server
{
    public class TgsState : PaDataState
    {
        /// <summary>
        /// The AP-REQ representing the ticket-granting-ticket in the PA-Data
        /// </summary>
        public KrbApReq ApReq { get; set; }

        /// <summary>
        /// The decrypted contents of the AP-REQ
        /// </summary>
        public DecryptedKrbApReq DecryptedApReq { get; set; }
    }
}