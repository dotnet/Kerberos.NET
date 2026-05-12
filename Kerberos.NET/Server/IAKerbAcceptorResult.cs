// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using Kerberos.NET.Crypto;

namespace Kerberos.NET.Server
{
    /// <summary>
    /// The result of a single step of IAKerb context acceptance.
    /// </summary>
    public class IAKerbAcceptorResult
    {
        /// <summary>
        /// The GSS token to send back to the initiator.
        /// Present during the proxy phase (when <see cref="IsComplete"/> is false).
        /// May also be present when complete if mutual authentication was requested (AP-REP).
        /// </summary>
        public ReadOnlyMemory<byte>? Token { get; }

        /// <summary>
        /// Whether context establishment is complete.
        /// When false, send <see cref="Token"/> to the initiator and continue the exchange.
        /// When true, the client has been authenticated.
        /// </summary>
        public bool IsComplete { get; }

        /// <summary>
        /// The decrypted AP-REQ from the authenticated client.
        /// Only available when <see cref="IsComplete"/> is true.
        /// </summary>
        public DecryptedKrbApReq DecryptedApReq { get; }

        internal IAKerbAcceptorResult(ReadOnlyMemory<byte>? token, bool isComplete, DecryptedKrbApReq decryptedApReq = null)
        {
            this.Token = token;
            this.IsComplete = isComplete;
            this.DecryptedApReq = decryptedApReq;
        }
    }
}
