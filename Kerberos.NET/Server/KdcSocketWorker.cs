using System;
using System.Buffers;
using System.Buffers.Binary;
using System.IO.Pipelines;
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

        public KdcSocketWorker(Socket socket, ListenerOptions options)
            : base(socket, options)
        {
            kdc = new KdcServer(options);
            logger = options.Log.CreateLoggerSafe<KdcSocketWorker>();
        }

        protected override async Task<ReadOnlyMemory<byte>> ProcessRequest(ReadOnlyMemory<byte> request, CancellationToken cancellation)
        {
            logger.LogTrace("Message incoming. Request length = {RequestLength}", request.Length);
            logger.TraceBinary(request);

            var response = await kdc.ProcessMessage(request);

            logger.LogTrace("Message processed. Response length = {ResponseLength}", response.Length);

            return response;
        }
    }
}
