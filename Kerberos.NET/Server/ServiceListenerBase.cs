// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Diagnostics;
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
            = new TaskCompletionSource<object>(TaskCreationOptions.RunContinuationsAsynchronously);

        private readonly Stack<SocketListener> openListeners = new Stack<SocketListener>();

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
            while (this.openListeners.Count != 0)
            {
                SocketListener listener = this.openListeners.Pop();
                listener.Dispose();
            }

            this.startTcs.SetResult(null);
        }

        private void StartListenerThreads(SocketListener listener)
        {
            _ = this.AcceptConnections(listener);
        }

        private async Task AcceptConnections(SocketListener socketListener)
        {
            if (socketListener == null)
            {
                return;
            }

            this.openListeners.Push(socketListener);

            SocketWorkerBase worker = null;
            try
            {
                while (true)
                {
                    try
                    {
                        worker = await socketListener.Accept().ConfigureAwait(false);
                    }
                    catch (Exception ex)
                    {
                        this.logger.LogWarning(ex, "Accept connection failed with exception");
                    }

                    if (worker == null)
                    {
                        break;
                    }

                    try
                    {
                        _ = worker.HandleSocket();
                    }
                    catch (Exception ex)
                    {
                        this.logger.LogWarning(ex, "Accept Handle Socket failed with exception");
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
    }
}
