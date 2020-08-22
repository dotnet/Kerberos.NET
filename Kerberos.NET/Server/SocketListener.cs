// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Kerberos.NET.Server
{
    internal class SocketListener : SocketBase
    {
        private readonly ILogger<SocketListener> logger;
        private readonly Socket listeningSocket;
        private readonly Func<Socket, KdcServerOptions, SocketWorkerBase> workerFunc;

        public SocketListener(KdcServerOptions options, Func<Socket, KdcServerOptions, SocketWorkerBase> workerFunc)
            : base(options)
        {
            this.logger = options.Log.CreateLoggerSafe<SocketListener>();

            this.listeningSocket = new Socket(SocketType.Stream, ProtocolType.Tcp);

            this.listeningSocket.Bind(this.Options.ListeningOn);
            this.listeningSocket.Listen(this.Options.QueueLength);

            this.logger.LogInformation(
                "Listener has started. Endpoint = {Port}; Protocol = {Protocol}",
                this.listeningSocket.LocalEndPoint,
                this.listeningSocket.ProtocolType
            );

            options.Cancellation = new CancellationTokenSource();

            this.workerFunc = workerFunc;
        }

        public async Task<SocketWorkerBase> Accept()
        {
            while (true)
            {
                if (this.Options.Cancellation.IsCancellationRequested)
                {
                    return null;
                }

                try
                {
                    var socket = await this.listeningSocket.AcceptAsync().ConfigureAwait(true);

                    return this.workerFunc(socket, this.Options);
                }
                catch (SocketException sx)
                    when (IsSocketAbort(sx.SocketErrorCode) || IsSocketError(sx.SocketErrorCode))
                {
                    this.logger.LogTrace(sx, "Accept exception raised by socket with code {Error}", sx.SocketErrorCode);
                    throw;
                }
                catch (ObjectDisposedException ex)
                {
                    this.logger.LogTrace(ex, "Accept exception raised because object was used after dispose");
                    throw;
                }
                catch (Exception ex)
                {
                    this.logger.LogTrace(ex, "Accept exception raised");
                    throw;
                }
            }
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);

            if (disposing)
            {
                this.Options.Cancellation.Cancel();

                this.listeningSocket.Dispose();
            }
        }
    }
}