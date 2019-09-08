using System;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace Kerberos.NET.Server
{
    internal class SocketListener : SocketBase
    {
        private readonly Socket listeningSocket;

        private readonly Func<Socket, ListenerOptions, SocketWorkerBase> workerFunc;

        public SocketListener(ListenerOptions options, Func<Socket, ListenerOptions, SocketWorkerBase> workerFunc)
            : base(options)
        {
            listeningSocket = new Socket(SocketType.Stream, ProtocolType.Tcp);

            listeningSocket.Bind(Options.ListeningOn);
            listeningSocket.Listen(Options.QueueLength);

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
                    LogVerbose(sx);
                }
                catch (ObjectDisposedException ex)
                {
                    LogVerbose(ex);
                }
                catch (Exception ex)
                {
                    Log(ex);
                }
            }
        }

        public override void Dispose()
        {
            listeningSocket.Dispose();
        }
    }
}
