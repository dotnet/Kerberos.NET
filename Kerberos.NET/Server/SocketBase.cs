// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Net.Sockets;
using System.Runtime.CompilerServices;

namespace Kerberos.NET.Server
{
    public abstract class SocketBase : IDisposable
    {
        private bool disposedValue;

        protected KdcServerOptions Options { get; }

        protected SocketBase(KdcServerOptions options)
        {
            this.Options = options;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        protected static bool IsSocketError(SocketError errorCode)
        {
            return errorCode == SocketError.ConnectionReset ||
                   errorCode == SocketError.Shutdown ||
                   errorCode == SocketError.ConnectionAborted;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        protected static bool IsSocketAbort(SocketError errorCode)
        {
            return errorCode == SocketError.OperationAborted ||
                   errorCode == SocketError.Interrupted;
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!this.disposedValue)
            {
                this.disposedValue = true;
            }
        }

        public void Dispose()
        {
            this.Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }
}