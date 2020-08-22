// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Diagnostics;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Kerberos.NET.Transport;
using Microsoft.Extensions.Logging;

namespace Kerberos.NET.Server
{
    public abstract class SocketWorkerBase : SocketBase
    {
        private readonly Socket socket;

        private readonly ILogger<SocketWorkerBase> logger;

        protected SocketWorkerBase(Socket socket, KdcServerOptions options)
            : base(options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            this.socket = socket;
            this.logger = options.Log.CreateLoggerSafe<SocketWorkerBase>();
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);

            if (disposing)
            {
                this.socket.Dispose();
            }
        }

        public async Task HandleSocket()
        {
            Trace.CorrelationManager.StartLogicalOperation();

            try
            {
                using (var cancellation = new CancellationTokenSource())
                {
                    do
                    {
                        if (this.Options.Cancellation.Token.IsCancellationRequested)
                        {
                            break;
                        }

                        using (this.logger.BeginRequestScope(this.Options.NextScopeId()))
                        {
                            using (var stream = new NetworkStream(this.socket))
                            {
                                await this.ProcessMessage(stream, this.Options.Cancellation.Token).ConfigureAwait(true);
                            }
                        }
                    }
                    while (true);
                }
            }
            finally
            {
                Trace.CorrelationManager.StopLogicalOperation();

                this.socket.Dispose();
            }
        }

        private async Task ProcessMessage(NetworkStream stream, CancellationToken cancellation)
        {
            var messageSizeBytes = await Tcp.ReadFromStream(4, stream, cancellation).ConfigureAwait(true);

            var messageSize = (int)messageSizeBytes.AsLong();

            var request = await Tcp.ReadFromStream(messageSize, stream, cancellation).ConfigureAwait(true);

            var response = await this.ProcessRequest(request, cancellation).ConfigureAwait(true);

            response = Tcp.FormatKerberosMessageStream(response);

            await stream.WriteAsync(response.ToArray(), 0, response.Length, cancellation).ConfigureAwait(true);
        }

        protected abstract Task<ReadOnlyMemory<byte>> ProcessRequest(ReadOnlyMemory<byte> request, CancellationToken cancellation);
    }
}