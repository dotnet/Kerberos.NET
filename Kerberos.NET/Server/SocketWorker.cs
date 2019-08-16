using System;
using System.Buffers;
using System.IO.Pipelines;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Kerberos.NET.Server
{
    public abstract class SocketWorkerBase : SocketBase
    {
        private readonly TaskCompletionSource<object> responseFilledCompletion = new TaskCompletionSource<object>();

        private readonly PipeScheduler scheduler = PipeScheduler.ThreadPool;

        private readonly Socket socket;

        protected Pipe RequestPipe { get; }

        protected Pipe ResponsePipe { get; }

        protected SocketWorkerBase(Socket socket, ListenerOptions options)
            : base(options)
        {
            this.socket = socket;

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

        protected abstract Task ReadRequest();

        protected abstract Task FillResponse(PipeWriter writer, ReadOnlyMemory<byte> message);

        public override void Dispose()
        {
            socket.Dispose();
        }

        public async Task HandleMessage()
        {
            var timeoutSource = new CancellationTokenSource(Options.ReceiveTimeout);
            var timeoutCompletion = new TaskCompletionSource<object>();

            timeoutSource.Token.Register(() => timeoutCompletion.TrySetCanceled(timeoutSource.Token));

            try
            {
                var receiving = Receive();
                var responding = Respond();

                if (await Task.WhenAny(receiving, responding, timeoutCompletion.Task) == timeoutCompletion.Task)
                {
                    throw new TimeoutException();
                }
            }
            catch (Exception ex)
            {
                Log(ex);
            }
            finally
            {
                timeoutSource.Dispose();

                Dispose();
            }
        }

        private async Task Respond()
        {
            try
            {
                var responseSent = SendResponse(ResponsePipe.Reader);

                await Task.WhenAll(responseFilledCompletion.Task, responseSent);
            }
            catch (SocketException sx)
                when (IsSocketAbort(sx.SocketErrorCode) || IsSocketError(sx.SocketErrorCode))
            {
                LogVerbose(sx);
            }
            catch (ObjectDisposedException ex)
            {
                LogVerbose(ex);
            }
            catch (Exception ex)
            {
                Log(ex);
                throw;
            }
        }

        private async Task SendResponse(PipeReader reader)
        {
            while (true)
            {
                var result = await reader.ReadAsync();

                var buffer = result.Buffer;

                if (buffer.Length <= 0)
                {
                    break;
                }
                await socket.SendAsync(new ArraySegment<byte>(buffer.ToArray()), SocketFlags.None);
                reader.AdvanceTo(buffer.Start, buffer.End);
            }

            reader.Complete();
        }

        private async Task Receive()
        {
            try
            {
                var fill = FillRequest(RequestPipe.Writer, async buffer =>
                {
                    var fillBuffer = new byte[buffer.Length];
                    var retval = await socket.ReceiveAsync(new ArraySegment<byte>(fillBuffer), SocketFlags.None);
                    fillBuffer.CopyTo(buffer);
                    return retval;
                });                
                var read = ReadRequest();

                await Task.WhenAll(fill, read);
                responseFilledCompletion.TrySetResult(null);
            }
            catch (SocketException sx) when (IsSocketAbort(sx.SocketErrorCode) || IsSocketError(sx.SocketErrorCode))
            {
                LogVerbose(sx);
            }
            catch (Exception ex)
            {
                Log(ex);
                throw;
            }
        }

        private static async Task FillRequest(PipeWriter writer, Func<Memory<byte>, ValueTask<int>> write)
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

                var result = await writer.FlushAsync();

                if (result.IsCompleted)
                {
                    break;
                }
            }

            writer.Complete();
        }
    }
}
