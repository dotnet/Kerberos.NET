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
    internal class KdcSocketWorker : SocketWorkerBase
    {
        private readonly KdcServer kdc;

        private readonly ILogger<KdcSocketWorker> logger;

        public KdcSocketWorker(Socket socket, KdcServerOptions options)
            : base(socket, options)
        {
            this.kdc = new KdcServer(options);
            this.logger = options.Log.CreateLoggerSafe<KdcSocketWorker>();
        }

        protected override async Task<ReadOnlyMemory<byte>> ProcessRequest(ReadOnlyMemory<byte> request, CancellationToken cancellation)
        {
            this.logger.LogTrace("Message incoming. Request length = {RequestLength}", request.Length);

            var response = await this.kdc.ProcessMessage(request).ConfigureAwait(false);

            this.logger.LogTrace("Message processed. Response length = {ResponseLength}", response.Length);

            return response;
        }
    }
}
