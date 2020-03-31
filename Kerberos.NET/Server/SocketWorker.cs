using Kerberos.NET.Transport;
using Microsoft.Extensions.Logging;
using System;
using System.Diagnostics;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Kerberos.NET.Server
{
    public abstract class SocketWorkerBase : SocketBase
    {
        private readonly Socket socket;

        private readonly ILogger<SocketWorkerBase> logger;

        protected SocketWorkerBase(Socket socket, ListenerOptions options)
            : base(options)
        {
            this.socket = socket;
            this.logger = options.Log.CreateLoggerSafe<SocketWorkerBase>();
        }

        public override void Dispose()
        {
            socket.Dispose();
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
                        if (Options.Cancellation.Token.IsCancellationRequested)
                        {
                            break;
                        }

                        using (logger.BeginRequestScope(Options.NextScopeId()))
                        {
                            var stream = new NetworkStream(socket);

                            await ProcessMessage(stream, Options.Cancellation.Token);
                        }
                    }
                    while (true);
                }
            }
            finally
            {
                Trace.CorrelationManager.StopLogicalOperation();

                socket.Dispose();
            }
        }

        private async Task ProcessMessage(NetworkStream stream, CancellationToken cancellation)
        {
            var messageSizeBytes = await Tcp.ReadFromStream(4, stream, cancellation);

            var messageSize = (int)messageSizeBytes.AsLong();

            var request = await Tcp.ReadFromStream(messageSize, stream, cancellation);

            var response = await ProcessRequest(request, cancellation);

            response = Tcp.FormatKerberosMessageStream(response);

            await stream.WriteAsync(response.ToArray(), 0, response.Length, cancellation);
        }

        protected abstract Task<ReadOnlyMemory<byte>> ProcessRequest(ReadOnlyMemory<byte> request, CancellationToken cancellation);
    }
}
