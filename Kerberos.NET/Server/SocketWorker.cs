using System;
using System.Buffers;
using System.Diagnostics;
using System.IO.Pipelines;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Kerberos.NET.Server
{
    public abstract class SocketWorkerBase : SocketBase
    {
        private readonly TaskCompletionSource<object> responseFilledCompletion = new TaskCompletionSource<object>();

        private readonly PipeScheduler scheduler = PipeScheduler.ThreadPool;

        private readonly Socket socket;

        private readonly ILogger<SocketWorkerBase> logger;

        protected Pipe RequestPipe { get; }

        protected Pipe ResponsePipe { get; }

        protected SocketWorkerBase(Socket socket, ListenerOptions options)
            : base(options)
        {
            this.socket = socket;
            this.logger = options.Log.CreateLoggerSafe<SocketWorkerBase>();

            RequestPipe = new Pipe(new PipeOptions(
                readerScheduler: scheduler,
                writerScheduler: scheduler,
                pauseWriterThreshold: options.MaxReadBufferSize,
                resumeWriterThreshold: options.MaxReadBufferSize / 2,
                useSynchronizationContext: false
            ));

            ResponsePipe = new Pipe(new PipeOptions(
                readerScheduler: scheduler,
                writerScheduler: scheduler,
                pauseWriterThreshold: options.MaxWriteBufferSize,
                resumeWriterThreshold: options.MaxWriteBufferSize / 2,
                useSynchronizationContext: false
            ));
        }

        protected abstract Task ReadRequest(CancellationToken cancellation);

        protected abstract Task FillResponse(PipeWriter writer, ReadOnlyMemory<byte> message, CancellationToken cancellation);

        public override void Dispose()
        {
            socket.Dispose();
        }

        public async Task HandleMessage()
        {
            Trace.CorrelationManager.StartLogicalOperation();

            try
            {

                using (logger.BeginRequestScope(Options.NextScopeId()))
                using (var timeoutSource = new CancellationTokenSource())
                using (var receiveTimeoutSource = new CancellationTokenSource())
                using (var acceptTimeoutSource = new CancellationTokenSource(Options.AcceptTimeout))
                {
                    receiveTimeoutSource.Token.Register(timeoutSource.Cancel);
                    acceptTimeoutSource.Token.Register(timeoutSource.Cancel);

                    var timeoutCompletion = new TaskCompletionSource<object>();

                    timeoutSource.Token.Register(() => timeoutCompletion.TrySetResult(timeoutSource.Token));

                    try
                    {
                        receiveTimeoutSource.CancelAfter(Options.ReceiveTimeout);

                        var receiving = Receive(timeoutSource.Token);
                        var responding = Respond(timeoutSource.Token);

                        var waitAll = Task.WhenAll(receiving, responding);

                        if (await Task.WhenAny(waitAll, timeoutCompletion.Task) == timeoutCompletion.Task)
                        {
                            throw new TimeoutException();
                        }
                    }
                    catch (Exception ex)
                    {
                        logger.LogWarning(ex, "Worker could not complete message handling");

                        Dispose();
                    }
                }
            }
            finally
            {
                Trace.CorrelationManager.StopLogicalOperation();
            }
        }

        private async Task Respond(CancellationToken cancellation)
        {
            try
            {
                var responseSent = SendResponse(ResponsePipe.Reader, cancellation);

                await Task.WhenAll(responseFilledCompletion.Task, responseSent);
            }
            catch (SocketException sx)
                when (IsSocketAbort(sx.SocketErrorCode) || IsSocketError(sx.SocketErrorCode))
            {
                logger.LogTrace(sx, "Worker response failed with socket error {Error}", sx.SocketErrorCode);
            }
            catch (ObjectDisposedException ex)
            {
                logger.LogTrace(ex, "Response exception raised because object was used after dispose");
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Response exception raised");
                throw;
            }
        }

        private async Task SendResponse(PipeReader reader, CancellationToken cancellation)
        {
            while (true)
            {
                if (cancellation.IsCancellationRequested)
                {
                    reader.CancelPendingRead();

                    break;
                }

                var result = await reader.ReadAsync(cancellation);

                if (result.IsCanceled)
                {
                    break;
                }

                var buffer = result.Buffer;

                if (buffer.Length <= 0)
                {
                    break;
                }

                byte[] fillBufferBytes = null;

                try
                {
                    if (!MemoryMarshal.TryGetArray(buffer.First, out ArraySegment<byte> fillBuffer))
                    {
                        fillBufferBytes = CryptoPool.Rent((int)buffer.Length);

                        fillBuffer = new ArraySegment<byte>(fillBufferBytes);
                    }

                    await socket.SendAsync(fillBuffer, SocketFlags.None);

                    if (result.IsCompleted)
                    {
                        break;
                    }
                }
                finally
                {
                    if (fillBufferBytes != null)
                    {
                        CryptoPool.Return(fillBufferBytes);
                    }
                }

                reader.AdvanceTo(buffer.Start, buffer.End);
            }

            reader.Complete();
        }

        private async Task Receive(CancellationToken cancellation)
        {
            try
            {
                var fill = FillRequest(RequestPipe.Writer, cancellation, async buffer =>
                {
                    byte[] fillBufferBytes = null;

                    try
                    {
                        if (!MemoryMarshal.TryGetArray(buffer, out ArraySegment<byte> fillBuffer))
                        {
                            fillBufferBytes = CryptoPool.Rent(buffer.Length);

                            fillBuffer = new ArraySegment<byte>(fillBufferBytes);
                        }

                        var bytesRead = await socket.ReceiveAsync(fillBuffer, SocketFlags.None);

                        if (fillBufferBytes != null)
                        {
                            fillBuffer.AsSpan(0, buffer.Length).CopyTo(buffer.Span);
                        }

                        return bytesRead;
                    }
                    finally
                    {
                        if (fillBufferBytes != null)
                        {
                            CryptoPool.Return(fillBufferBytes);
                        }
                    }
                });

                var read = ReadRequest(cancellation);

                await Task.WhenAll(fill, read);
            }
            catch (SocketException sx)
                when (IsSocketAbort(sx.SocketErrorCode) || IsSocketError(sx.SocketErrorCode))
            {
                logger.LogTrace(sx, "Worker receive failed with socket error {Error}", sx.SocketErrorCode);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Receive exception raised");
            }
            finally
            {
                responseFilledCompletion.TrySetResult(null);
            }
        }

        private static async Task FillRequest(PipeWriter writer, CancellationToken cancellation, Func<Memory<byte>, ValueTask<int>> write)
        {
            while (true)
            {
                var buffer = writer.GetMemory();

                var bytesRead = await write(buffer);

                if (bytesRead == 0)
                {
                    break;
                }

                writer.Advance(bytesRead);

                var result = await writer.FlushAsync(cancellation);

                if (result.IsCompleted)
                {
                    break;
                }

                if (cancellation.IsCancellationRequested)
                {
                    writer.CancelPendingFlush();
                    break;
                }
            }

            writer.Complete();
        }
    }
}
