using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Net.Sockets;
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

        private readonly ILogger<ServiceListenerBase> logger;

        protected ServiceListenerBase(
            ListenerOptions options,
            Func<Socket, ListenerOptions, SocketWorkerBase> workerFunc
        )
        {
            Options = options;

            logger = options.Log.CreateLoggerSafe<ServiceListenerBase>();
            socketListener = new SocketListener(options, workerFunc);
        }

        public ListenerOptions Options { get; }


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

            startTcs.SetResult(null);
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
                logger.LogWarning(ex, "Accept connection failed with exception");
            }
            finally
            {
                Stop();
            }
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
