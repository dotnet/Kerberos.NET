// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Globalization;
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

            // open the port 88 socket here so it can start listening

            this.listeningSocket = BindSocket(
                this.Options.Configuration.KdcDefaults.KdcTcpListenEndpoints,
                this.Options.Configuration.KdcDefaults.TcpListenBacklog
            );

            this.logger.LogInformation(
                "Listener has started. Endpoint = {Port}; Protocol = {Protocol}",
                this.listeningSocket.LocalEndPoint,
                this.listeningSocket.ProtocolType
            );

            if (options.Cancellation == null)
            {
                options.Cancellation = new CancellationTokenSource();
            }

            this.workerFunc = workerFunc;
        }

        private static Socket BindSocket(IEnumerable<string> endpoints, int backlog)
        {
            var listeningSocket = new Socket(SocketType.Stream, ProtocolType.Tcp);

            foreach (var endpoint in endpoints)
            {
                listeningSocket.Bind(ParseAddress(endpoint));
            }

            listeningSocket.Listen(backlog * 1000);

            return listeningSocket;
        }

        private static EndPoint ParseAddress(string endpoint)
        {
            if (TryParse(endpoint, DefaultKdcPort, out IPEndPoint result))
            {
                return result;
            }

            throw new FormatException($"Endpoint is malformed: {endpoint}");
        }

        private static bool TryParse(string addr, int defaultPort, out IPEndPoint result)
        {
            var s = addr.AsSpan();

            int addressLength = s.Length;
            int lastColonPos = s.LastIndexOf(':');

            if (lastColonPos > 0)
            {
                if (s[lastColonPos - 1] == ']')
                {
                    addressLength = lastColonPos;
                }
                else if (s.Slice(0, lastColonPos).LastIndexOf(':') == -1)
                {
                    addressLength = lastColonPos;
                }
            }

            if (IPAddress.TryParse(s.Slice(0, addressLength).ToString(), out IPAddress address))
            {
                uint port = (uint)defaultPort;

                if (addressLength == s.Length ||
                    (uint.TryParse(s.Slice(addressLength + 1).ToString(), NumberStyles.None, CultureInfo.InvariantCulture, out port) && port <= IPEndPoint.MaxPort))

                {
                    result = new IPEndPoint(address, (int)port);
                    return true;
                }
            }

            result = null;
            return false;
        }

        public async Task<SocketWorkerBase> Accept()
        {
            while (true)
            {
                if (this.Options.Cancellation.IsCancellationRequested)
                {
                    return null;
                }

                // on every loop we wait until a new connection comes in and then accept that connection
                // so the worker can process all messages on that socket

                var socket = await this.listeningSocket.AcceptAsync()
                                                       .ConfigureAwait(false);

                return this.workerFunc(socket, this.Options);
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
