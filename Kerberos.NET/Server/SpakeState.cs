// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

namespace Kerberos.NET.Server
{
    /// <summary>
    /// Contains the state information of a SPAKE pre-authentication exchange
    /// used between the pre-validation and validation phases.
    /// </summary>
    public class SpakeState : PaDataState
    {
        /// <summary>
        /// The SPAKE group selected for this exchange.
        /// </summary>
        public Configuration.SpakePreAuthGroupType SelectedGroup { get; set; }

        /// <summary>
        /// Indicates the challenge has been sent and we're awaiting a response.
        /// </summary>
        public bool ChallengeSent { get; set; }

        /// <summary>
        /// The server's SPAKE private scalar value for this exchange.
        /// </summary>
        public byte[] ServerPrivateKey { get; set; }

        /// <summary>
        /// The derived shared secret from the SPAKE exchange.
        /// </summary>
        public byte[] SharedSecret { get; set; }
    }
}
