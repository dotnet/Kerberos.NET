// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;

namespace Kerberos.NET.Entities.GssApi
{
    /// <summary>
    /// Represents a GSS-API security context handle.
    /// </summary>
    public class GssSecurityContext : IDisposable
    {
        private bool disposed = false;

        /// <summary>
        /// Gets or sets the internal context identifier.
        /// </summary>
        internal object InternalContext { get; set; }

        /// <summary>
        /// Gets or sets the mechanism OID for this context.
        /// </summary>
        public GssOid MechType { get; set; }

        /// <summary>
        /// Gets or sets the source (initiator) name.
        /// </summary>
        public GssName SourceName { get; set; }

        /// <summary>
        /// Gets or sets the target (acceptor) name.
        /// </summary>
        public GssName TargetName { get; set; }

        /// <summary>
        /// Gets or sets the context flags.
        /// </summary>
        public GssContextEstablishmentFlag Flags { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the context is fully established.
        /// </summary>
        public bool IsEstablished { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether this context was locally initiated.
        /// </summary>
        public bool LocallyInitiated { get; set; }

        /// <summary>
        /// Gets or sets the context lifetime in seconds.
        /// </summary>
        public uint Lifetime { get; set; }

        /// <summary>
        /// Gets or sets the session key.
        /// </summary>
        public ReadOnlyMemory<byte> SessionKey { get; internal set; }

        /// <summary>
        /// Represents an uninitialized context handle.
        /// </summary>
        public static readonly GssSecurityContext GSS_C_NO_CONTEXT = null;

        protected virtual void Dispose(bool disposing)
        {
            if (!disposed)
            {
                if (disposing)
                {
                    SourceName?.Dispose();
                    TargetName?.Dispose();
                    InternalContext = null;
                    SessionKey = ReadOnlyMemory<byte>.Empty;
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
