// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Buffers.Binary;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Kerberos.NET.Logging;
using Kerberos.NET.Transport;
using Microsoft.Extensions.Logging;

namespace Kerberos.NET.Server
{
    /// <summary>
    /// Receives a socket after Accept() to communicate with the client
    /// </summary>
    public abstract class SocketWorkerBase : SocketBase
    {
        private readonly Socket socket;
        private readonly ILogger<SocketWorkerBase> logger;

        protected SocketWorkerBase(Socket socket, KdcServerOptions options)
            : base(options)
        {
            if (socket == null)
            {
                throw new ArgumentNullException(nameof(socket));
            }

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
            if (this.Disposed)
            {
                throw new NotSupportedException("Cannot reuse worker after it's been disposed");
            }

            try
            {
                using (socket)
                using (var cancellation = CancellationTokenSource.CreateLinkedTokenSource(this.Options.Cancellation.Token))
                {
                    while (!cancellation.IsCancellationRequested)
                    {
                        try
                        {
                            await ReceiveMessage(cancellation).ConfigureAwait(false);
                        }
                        catch (IOException ex)
                            when (ex.InnerException is SocketException sx)
                        {
                            if (!ServiceListenerBase.IsSocketAbort(sx.SocketErrorCode) &&
                                !ServiceListenerBase.IsSocketError(sx.SocketErrorCode))
                            {
                                this.logger.LogWarning(ex, "SocketWorker message receive failed");
                            }

                            cancellation.Cancel();
                        }
                    }
                }
            }
            finally
            {
                this.Dispose();
            }
        }

        private async Task ReceiveMessage(CancellationTokenSource cancellation)
        {
            using (TraceOperation.Start())
            using (this.logger.BeginRequestScope(this.Options.NextScopeId()))
            using (var stream = new NetworkStream(this.socket, ownsSocket: false))
            {
                var receiveTimeout = this.Options.Configuration.KdcDefaults.ReceiveTimeout;

                stream.ReadTimeout = (int)receiveTimeout.TotalMilliseconds / 2;

                await this.ProcessMessage(stream, cancellation.Token, receiveTimeout).ConfigureAwait(false);
            }
        }

        private async Task ProcessMessage(NetworkStream stream, CancellationToken cancellation, TimeSpan receiveTimeout)
        {
            using (var sizeRented = CryptoPool.Rent<byte>(4))
            {
                var messageSizeBytes = sizeRented.Memory.Slice(0, 4);

                await Tcp.ReadFromStream(messageSizeBytes, stream, cancellation, receiveTimeout).ConfigureAwait(false);

                var messageSize = BinaryPrimitives.ReadInt32BigEndian(messageSizeBytes.Span);

                using (var requestRented = CryptoPool.Rent<byte>(messageSize))
                {
                    var request = requestRented.Memory.Slice(0, messageSize);

                    await Tcp.ReadFromStream(request, stream, cancellation, receiveTimeout).ConfigureAwait(false);

                    var response = await this.ProcessRequest(request, cancellation).ConfigureAwait(false);

                    var responseLength = response.Length + 4;

                    using (var responseRented = CryptoPool.Rent<byte>(responseLength))
                    {
                        var formattedResponse = responseRented.Memory.Slice(0, responseLength);

                        Tcp.FormatKerberosMessageStream(response, formattedResponse);

                        await stream.WriteAsync(formattedResponse, cancellation).ConfigureAwait(false);
                    }
                }
            }
        }

        protected abstract Task<ReadOnlyMemory<byte>> ProcessRequest(ReadOnlyMemory<byte> request, CancellationToken cancellation);
    }
}
