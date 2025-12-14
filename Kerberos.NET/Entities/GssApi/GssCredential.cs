// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using Kerberos.NET.Credentials;

namespace Kerberos.NET.Entities.GssApi
{
    /// <summary>
    /// Credential usage options.
    /// </summary>
    [Flags]
    public enum GssCredentialUsage
    {
        /// <summary>
        /// Credentials may be used either to initiate or accept security contexts.
        /// </summary>
        GSS_C_BOTH = 0,

        /// <summary>
        /// Credentials will only be used to initiate security contexts.
        /// </summary>
        GSS_C_INITIATE = 1,

        /// <summary>
        /// Credentials will only be used to accept security contexts.
        /// </summary>
        GSS_C_ACCEPT = 2,
    }

    /// <summary>
    /// Represents a GSS-API credential handle.
    /// </summary>
    public class GssCredential : IDisposable
    {
        private bool disposed = false;

        /// <summary>
        /// Initializes a new instance of the <see cref="GssCredential"/> class.
        /// </summary>
        /// <param name="credential">The underlying Kerberos credential.</param>
        /// <param name="usage">The credential usage.</param>
        public GssCredential(KerberosCredential credential, GssCredentialUsage usage = GssCredentialUsage.GSS_C_BOTH)
        {
            this.Credential = credential ?? throw new ArgumentNullException(nameof(credential));
            this.Usage = usage;
        }

        /// <summary>
        /// Gets the underlying Kerberos credential.
        /// </summary>
        public KerberosCredential Credential { get; private set; }

        /// <summary>
        /// Gets the credential usage.
        /// </summary>
        public GssCredentialUsage Usage { get; }

        /// <summary>
        /// Gets the principal name associated with the credential.
        /// </summary>
        public GssName Name { get; internal set; }

        /// <summary>
        /// Gets the lifetime of the credential in seconds.
        /// </summary>
        public uint Lifetime { get; internal set; }

        /// <summary>
        /// Gets the mechanisms supported by this credential.
        /// </summary>
        public GssOidSet Mechanisms { get; internal set; }

        /// <summary>
        /// Represents the default credential.
        /// </summary>
        public static readonly GssCredential GSS_C_NO_CREDENTIAL = null;

        protected virtual void Dispose(bool disposing)
        {
            if (!disposed)
            {
                if (disposing)
                {
                    Credential = null;
                    Name?.Dispose();
                    Mechanisms?.Dispose();
                }

                disposed = true;
            }
        }

        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }
}
