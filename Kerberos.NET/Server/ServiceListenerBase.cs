// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

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
            = new(TaskCreationOptions.RunContinuationsAsynchronously);

        private readonly Stack<SocketListener> openListeners = new();

        private readonly ILogger<ServiceListenerBase> logger;
        private bool disposedValue;

        protected ServiceListenerBase(
            KdcServerOptions options,
            Func<Socket, KdcServerOptions, SocketWorkerBase> workerFunc
        )
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            this.Options = options;

            this.logger = options.Log.CreateLoggerSafe<ServiceListenerBase>();
            this.socketListener = new SocketListener(options, workerFunc);
        }

        public KdcServerOptions Options { get; }

        public Task Start()
        {
            ThreadPool.QueueUserWorkItem(state => this.StartListenerThreads((SocketListener)state), this.socketListener);
            return this.startTcs.Task;
        }

        public void Stop()
        {
            this.Options.Cancellation.Cancel();

            this.logger.LogInformation("Service Listener stopping...");

            while (this.openListeners.Count != 0)
            {
                SocketListener listener = this.openListeners.Pop();
                listener.Dispose();
            }

            this.startTcs.SetResult(null);
        }

        private void StartListenerThreads(SocketListener listener)
        {
            // listener is the thing on port 88 waiting for clients to make the first connection

            _ = this.AcceptConnections(listener);
        }

        private async Task AcceptConnections(SocketListener socketListener)
        {
            if (socketListener == null)
            {
                return;
            }

            this.openListeners.Push(socketListener);

            SocketWorkerBase worker;

            try
            {
                while (!this.Options.Cancellation.IsCancellationRequested)
                {
                    try
                    {
                        // socketListener will wait until a client connects and accept's the connection
                        // accept transfers the connection to a separate socket and hands it off to
                        // a worker that will continue listening on that socket and process
                        // messages until the socket is closed by the client or timeout

                        worker = await socketListener.Accept().ConfigureAwait(false);

                        // worker will spin until the socket is closed or timed out allowing
                        // clients to reuse existing socket connections to the KDC

                        _ = worker.HandleSocket();
                    }
                    catch (SocketException sx)
                        when (IsSocketAbort(sx.SocketErrorCode) || IsSocketError(sx.SocketErrorCode))
                    {
                        this.logger.LogTrace(sx, "Accept exception raised by socket with code {Error}", sx.SocketErrorCode);
                        continue;
                    }
                    catch (ObjectDisposedException ex)
                    {
                        this.logger.LogTrace(ex, "Accept exception raised because object was used after dispose");
                        continue;
                    }
                    catch (Exception ex)
                    {
                        this.logger.LogTrace(ex, "Accept exception raised for unknown reason");
                        break;
                    }

                    if (worker == null)
                    {
                        break;
                    }
                }
            }
            finally
            {
                this.Stop();
            }
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!this.disposedValue)
            {
                if (disposing)
                {
                    this.socketListener.Dispose();
                }

                this.disposedValue = true;
            }
        }

        public void Dispose()
        {
            this.Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        internal static bool IsSocketError(SocketError errorCode)
        {
            return errorCode == SocketError.ConnectionReset ||
                   errorCode == SocketError.Shutdown ||
                   errorCode == SocketError.ConnectionAborted;
        }

        internal static bool IsSocketAbort(SocketError errorCode)
        {
            return errorCode == SocketError.OperationAborted ||
                   errorCode == SocketError.Interrupted;
        }
    }
}
