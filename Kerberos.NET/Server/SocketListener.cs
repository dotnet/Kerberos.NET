// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Kerberos.NET.Server
{
    internal class SocketListener : SocketBase
    {
        private const int DefaultKdcPort = 88;

        private readonly ILogger<SocketListener> logger;
        private readonly Socket listeningSocket;
        private readonly Func<Socket, KdcServerOptions, SocketWorkerBase> workerFunc;

        public SocketListener(KdcServerOptions options, Func<Socket, KdcServerOptions, SocketWorkerBase> workerFunc)
            : base(options)
        {
            this.logger = options.Log.CreateLoggerSafe<SocketListener>();
            this.listeningSocket = new Socket(SocketType.Stream, ProtocolType.Tcp);

            this.BindSocket();

            this.logger.LogInformation(
                "Listener has started. Endpoint = {Port}; Protocol = {Protocol}",
                this.listeningSocket.LocalEndPoint,
                this.listeningSocket.ProtocolType
            );

            options.Cancellation = new CancellationTokenSource();

            this.workerFunc = workerFunc;
        }

        private void BindSocket()
        {
            foreach (var endpoint in this.Options.Configuration.KdcDefaults.KdcTcpListenEndpoints)
            {
                this.listeningSocket.Bind(ParseAddress(endpoint));
            }

            this.listeningSocket.Listen(this.Options.Configuration.KdcDefaults.TcpListenBacklog * 100);
        }

        private static EndPoint ParseAddress(string endpoint)
        {
            var split = endpoint.Split(':');

            if (IPAddress.TryParse(split[0], out IPAddress addr))
            {
                if (split.Length == 1)
                {
                    return new IPEndPoint(addr, DefaultKdcPort);
                }
                else if (split.Length == 2 && int.TryParse(split[1], out int port))
                {
                    return new IPEndPoint(addr, port);
                }
            }

            throw new FormatException($"Endpoint is malformed: {endpoint}");
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
                    var socket = await this.listeningSocket.AcceptAsync().ConfigureAwait(false);

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
                    this.logger.LogTrace(ex, "Accept exception raised for unknown reason");
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
