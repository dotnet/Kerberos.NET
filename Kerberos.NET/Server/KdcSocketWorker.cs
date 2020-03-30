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

        protected override async Task ReadRequest(CancellationToken cancellation)
        {
            var reader = RequestPipe.Reader;

            long messageLength = 0;

            try
            {
                while (true)
                {
                    if (cancellation.IsCancellationRequested)
                    {
                        reader.CancelPendingRead();
                        break;
                    }

                    var result = await reader.ReadAsync(cancellation);

                    var buffer = result.Buffer;

                    if (messageLength <= 0)
                    {
                        messageLength = buffer.Slice(0, sizeof(int)).AsLong();
                    }

                    if (buffer.Length > messageLength)
                    {
                        var message = buffer.Slice(sizeof(int), messageLength);

                        await ProcessMessage(message, cancellation);
                        break;
                    }

                    reader.AdvanceTo(buffer.Start, buffer.End);

                    if (result.IsCompleted)
                    {
                        break;
                    }
                }
            }
            finally
            {
                reader.Complete();
            }
        }

        protected override async Task FillResponse(PipeWriter writer, ReadOnlyMemory<byte> message, CancellationToken cancellation)
        {
            var totalLength = message.Length + sizeof(int);

            if (totalLength > sizeof(int))
            {
                var buffer = writer.GetMemory(totalLength);

                BinaryPrimitives.WriteInt32BigEndian(buffer.Span.Slice(0, sizeof(int)), message.Length);

                message.CopyTo(buffer.Slice(sizeof(int), message.Length));

                writer.Advance(totalLength);
            }

            await writer.FlushAsync(cancellation);
            writer.Complete();
        }

        private async Task ProcessMessage(ReadOnlySequence<byte> message, CancellationToken cancellation)
        {
            logger.LogTrace("Message incoming. Request length = {RequestLength}", message.Length);
            logger.TraceBinary(message);

            var response = await kdc.ProcessMessage(message);

            logger.LogTrace("Message processed. Response length = {ResponseLength}", response.Length);

            await FillResponse(ResponsePipe.Writer, response, cancellation);
        }
    }
}
