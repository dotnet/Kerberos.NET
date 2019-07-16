using System;
using System.Net.Sockets;

namespace Kerberos.NET.Server
{
    internal abstract class SocketBase : IDisposable
    {
        protected KdcListenerOptions Options { get; }

        protected SocketBase(KdcListenerOptions options)
        {
            this.Options = options;
        }

        protected void Log(Exception ex)
        {
            if (Options.Log != null)
            {
                Options.Log.WriteLine(KerberosLogSource.ServiceListener, ex);
            }
        }

        protected void LogVerbose(Exception ex)
        {
            if (Options.Log != null && Options.Log.Level >= LogLevel.Verbose)
            {
                Log(ex);
            }
        }

        protected static bool IsSocketError(SocketError errorCode)
        {
            return errorCode == SocketError.ConnectionReset ||
                   errorCode == SocketError.Shutdown ||
                   errorCode == SocketError.ConnectionAborted;
        }

        protected static bool IsSocketAbort(SocketError errorCode)
        {
            return errorCode == SocketError.OperationAborted ||
                   errorCode == SocketError.Interrupted;
        }

        public abstract void Dispose();
    }
}
