using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;

namespace Kerberos.NET.Server
{
    public abstract class ServiceListenerBase : IDisposable
    {
        // - spin up sockets
        // - on Accept => dispatch to handler
        // - on handler => parse length, then read in message
        // - on message => decode type, pass to kdc

        private readonly SocketListener socketListener;

        private readonly TaskCompletionSource<object> startTcs
            = new TaskCompletionSource<object>(TaskCreationOptions.RunContinuationsAsynchronously);

        private readonly Stack<SocketListener> openListeners = new Stack<SocketListener>();

        public ListenerOptions Options { get; }

        protected ServiceListenerBase(
            ListenerOptions options, 
            Func<Socket, ListenerOptions, SocketWorkerBase> workerFunc
        )
        {
            Options = options;
            socketListener = new SocketListener(options, workerFunc);
        }

        public Task Start()
        {
            ThreadPool.QueueUserWorkItem(state => StartListenerThreads((SocketListener)state), socketListener);
            return startTcs.Task;
        }

        public void Stop()
        {
            while (openListeners.Count != 0)
            {
                SocketListener listener = openListeners.Pop();
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

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        protected void Log(Exception ex)
        {
            Options?.Log?.WriteLine(KerberosLogSource.ServiceListener, ex);
        }

        public virtual void Dispose()
        {
            if (socketListener != null)
            {
                socketListener.Dispose();
            }
        }
    }
}
