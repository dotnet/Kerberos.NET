using Kerberos.NET.Asn1;
using Kerberos.NET.Crypto;
using System;
using System.Buffers;
using System.IO.Pipelines;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Kerberos.NET.Server
{
    internal class SocketWorker : SocketBase
    {
        private const int Int32Size = 4;

        private readonly TaskCompletionSource<object> responseFilledCompletion = new TaskCompletionSource<object>();

        private readonly PipeScheduler scheduler = PipeScheduler.ThreadPool;

        private readonly Socket socket;
        private readonly Pipe requestPipe;
        private readonly Pipe responsePipe;

        private readonly KdcServer kdc;

        public SocketWorker(Socket socket, KdcListenerOptions options)
            : base(options)
        {
            this.socket = socket;

            kdc = new KdcServer(options);

            var requestOptions = new PipeOptions(
                readerScheduler: scheduler,
                writerScheduler: scheduler,
                pauseWriterThreshold: options.MaxReadBufferSize,
                resumeWriterThreshold: options.MaxReadBufferSize / 2,
                useSynchronizationContext: false
            );

            var responseOptions = new PipeOptions(
                readerScheduler: scheduler,
                writerScheduler: scheduler,
                pauseWriterThreshold: options.MaxWriteBufferSize,
                resumeWriterThreshold: options.MaxWriteBufferSize / 2,
                useSynchronizationContext: false
            );

            requestPipe = new Pipe(requestOptions);
            responsePipe = new Pipe(responseOptions);
        }

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
                var responseSent = SendResponse(responsePipe.Reader);

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

                await socket.SendAsync(buffer.ToArray(), SocketFlags.None);

                reader.AdvanceTo(buffer.Start, buffer.End);
            }

            reader.Complete();
        }

        private async Task Receive()
        {
            try
            {
                var fill = FillRequest(requestPipe.Writer, buffer => socket.ReceiveAsync(buffer, SocketFlags.None));
                var read = ReadRequest(requestPipe.Reader);

                await Task.WhenAll(fill, read);
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

        private async Task ReadRequest(PipeReader reader)
        {
            long messageLength = 0;

            while (true)
            {
                var result = await reader.ReadAsync();

                var buffer = result.Buffer;

                if (messageLength <= 0)
                {
                    messageLength = buffer.Slice(0, Int32Size).AsLong();
                }

                if (buffer.Length > messageLength)
                {
                    var message = buffer.Slice(Int32Size, messageLength);

                    await ProcessMessage(message);
                    break;
                }

                reader.AdvanceTo(buffer.Start, buffer.End);

                if (result.IsCompleted)
                {
                    break;
                }
            }

            reader.Complete();
        }

        private async Task ProcessMessage(ReadOnlySequence<byte> message)
        {
            if (Options.Log != null && Options.Log.Level >= LogLevel.Debug)
            {
                Options.Log.WriteLine(KerberosLogSource.ServiceListener, Environment.NewLine + message.ToArray().HexDump());
            }

            var response = await kdc.ProcessMessage(message);

            await FillResponse(responsePipe.Writer, response);

            responseFilledCompletion.TrySetResult(null);
        }

        private static async Task FillResponse(PipeWriter writer, ReadOnlyMemory<byte> message)
        {
            var totalLength = message.Length + Int32Size;

            if (totalLength > Int32Size)
            {
                var buffer = writer.GetMemory(totalLength);

                Endian.ConvertToBigEndian(message.Length, buffer.Slice(0, Int32Size));

                message.CopyTo(buffer.Slice(Int32Size, message.Length));

                writer.Advance(totalLength);
            }

            await writer.FlushAsync();
            writer.Complete();
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
