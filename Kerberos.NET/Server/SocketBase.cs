using System;
using System.Net.Sockets;
using System.Runtime.CompilerServices;

namespace Kerberos.NET.Server
{
    public abstract class SocketBase : IDisposable
    {
        protected ListenerOptions Options { get; }

        protected SocketBase(ListenerOptions options)
        {
            this.Options = options;
        }

        public abstract void Dispose();

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
    }
}
