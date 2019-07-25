using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Kerberos.NET.Server
{
    public abstract class ServiceListenerBase : IDisposable
    {
        // - spin up UDP+TCP sockets
        // - on Accept => dispatch to handler
        // - on handler => parse length, then read in message
        // - on message => decode type, pass to kdc

        private readonly SocketListener tcpSocketListener;
        private readonly ListenerOptions options;

        private readonly TaskCompletionSource<object> startTcs
            = new TaskCompletionSource<object>(TaskCreationOptions.RunContinuationsAsynchronously);

        private readonly Stack<SocketListener> openListeners = new Stack<SocketListener>();

        protected ServiceListenerBase(ListenerOptions options, Func<Socket, ListenerOptions, SocketWorker> workerFunc)
        {
            this.options = options;
            tcpSocketListener = new SocketListener(options, workerFunc);
        }

        public Task Start()
        {
            ThreadPool.QueueUserWorkItem(StartListenerThreads, tcpSocketListener, preferLocal: false);

            return startTcs.Task;
        }

        public void Stop()
        {
            while (openListeners.TryPop(out SocketListener listener))
            {
                listener.Dispose();
            }

            startTcs.TrySetResult(null);
        }

        private void StartListenerThreads(SocketListener listener)
        {
            _ = AcceptConnections(listener);
        }

        private async Task AcceptConnections(SocketListener socketListener)
        {
            if (socketListener == null)
            {
                return;
            }

            openListeners.Push(socketListener);

            try
            {
                while (true)
                {
                    var worker = await socketListener.Accept();

                    if (worker == null)
                    {
                        break;
                    }

                    _ = worker.HandleMessage();
                }
            }
            catch (Exception ex)
            {
                Log(ex);
            }
            finally
            {
                Stop();
            }
        }

        protected void Log(Exception ex)
        {
            if (options.Log != null)
            {
                options.Log.WriteLine(KerberosLogSource.ServiceListener, ex);
            }
        }

        public virtual void Dispose()
        {
            if (tcpSocketListener != null)
            {
                tcpSocketListener.Dispose();
            }
        }
    }
}
