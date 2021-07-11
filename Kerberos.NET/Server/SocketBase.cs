// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;

namespace Kerberos.NET.Server
{
    public abstract class SocketBase : IDisposable
    {
        protected KdcServerOptions Options { get; }

        protected bool Disposed { get; private set; }

        protected SocketBase(KdcServerOptions options)
        {
            this.Options = options;
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!this.Disposed)
            {
                this.Disposed = true;
            }
        }

        public void Dispose()
        {
            this.Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }
}
