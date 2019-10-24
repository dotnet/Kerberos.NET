using Microsoft.Extensions.Logging;
using System;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace Kerberos.NET.Server
{
    internal class SocketListener : SocketBase
    {
        private readonly ILogger<SocketListener> logger;
        private readonly Socket listeningSocket;
        private readonly Func<Socket, ListenerOptions, SocketWorkerBase> workerFunc;

        public SocketListener(ListenerOptions options, Func<Socket, ListenerOptions, SocketWorkerBase> workerFunc)
            : base(options)
        {
            logger = options.Log.CreateLoggerSafe<SocketListener>();

            listeningSocket = new Socket(SocketType.Stream, ProtocolType.Tcp);

            listeningSocket.Bind(Options.ListeningOn);
            listeningSocket.Listen(Options.QueueLength);

            logger.LogInformation("Listener has started. Endpoint = {Port}; Protocol = {Protocol}", listeningSocket.LocalEndPoint, listeningSocket.ProtocolType);

            this.workerFunc = workerFunc;
        }

        public async Task<SocketWorkerBase> Accept()
        {
            while (true)
            {
                try
                {
                    var socket = await listeningSocket.AcceptAsync();

                    return workerFunc(socket, Options);
                }
                catch (SocketException sx)
                    when (IsSocketAbort(sx.SocketErrorCode) || IsSocketError(sx.SocketErrorCode))
                {
                    logger.LogTrace(sx, "Accept exception raised by socket with code {Error}", sx.SocketErrorCode);
                }
                catch (ObjectDisposedException ex)
                {
                    logger.LogTrace(ex, "Accept exception raised because object was used after dispose");
                }
                catch (Exception ex)
                {
                    logger.LogTrace(ex, "Accept exception raised");
                    throw;
                }
            }
        }

        public override void Dispose()
        {
            listeningSocket.Dispose();
        }
    }
}
