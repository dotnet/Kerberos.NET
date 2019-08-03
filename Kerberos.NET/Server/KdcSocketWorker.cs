using Kerberos.NET.Asn1;
using Kerberos.NET.Crypto;
using System;
using System.Buffers;
using System.IO.Pipelines;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace Kerberos.NET.Server
{
    internal class KdcSocketWorker : SocketWorkerBase
    {
        private const int Int32Size = 4;

        private readonly KdcServer kdc;

        public KdcSocketWorker(Socket socket, ListenerOptions options)
            : base(socket, options)
        {
            kdc = new KdcServer(options);
        }

        protected override async Task ReadRequest()
        {
            var reader = RequestPipe.Reader;

            long messageLength = 0;

            try
            {
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
            }
            finally
            {
                reader.Complete();
            }
        }

        protected override async Task FillResponse(PipeWriter writer, ReadOnlyMemory<byte> message)
        {
            var minResponseLength = Int32Size;

            var totalLength = message.Length + minResponseLength;

            if (totalLength > minResponseLength)
            {
                var buffer = writer.GetMemory(totalLength);

                Endian.ConvertToBigEndian(message.Length, buffer.Slice(0, Int32Size));

                message.CopyTo(buffer.Slice(minResponseLength, message.Length));

                writer.Advance(totalLength);
            }

            await writer.FlushAsync();
            writer.Complete();
        }

        private async Task ProcessMessage(ReadOnlySequence<byte> message)
        {
            if (Options.Log != null && Options.Log.Level >= LogLevel.Debug)
            {
                Options.Log.WriteLine(KerberosLogSource.ServiceListener, Environment.NewLine + message.ToArray().HexDump());
            }

            var response = await kdc.ProcessMessage(message);

            await FillResponse(ResponsePipe.Writer, response);
        }
    }
}
