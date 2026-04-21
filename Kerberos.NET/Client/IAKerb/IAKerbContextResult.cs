// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;

namespace Kerberos.NET.Client
{
    /// <summary>
    /// The result of a single step of IAKerb context establishment.
    /// </summary>
    public class IAKerbContextResult
    {
        /// <summary>
        /// The GSS token to send to the peer. Always present.
        /// </summary>
        public ReadOnlyMemory<byte> Token { get; }

        /// <summary>
        /// Whether the context establishment is still in progress.
        /// When true, send <see cref="Token"/> to the peer and feed their response
        /// into the next call. When false, authentication is complete.
        /// </summary>
        public bool ContinueNeeded { get; }

        /// <summary>
        /// The session context for the authenticated connection.
        /// Only available when <see cref="ContinueNeeded"/> is false.
        /// </summary>
        public ApplicationSessionContext SessionContext { get; }

        internal IAKerbContextResult(ReadOnlyMemory<byte> token, bool continueNeeded, ApplicationSessionContext sessionContext = null)
        {
            this.Token = token;
            this.ContinueNeeded = continueNeeded;
            this.SessionContext = sessionContext;
        }
    }
}
