using System;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace Kerberos.NET.Server
{
    internal class SocketListener : SocketBase
    {
        private readonly Socket listeningSocket;

        public SocketListener(KdcListenerOptions options)
            : base(options)
        {
            listeningSocket = new Socket(SocketType.Stream, ProtocolType.Tcp);

            listeningSocket.Bind(Options.ListeningOn);
            listeningSocket.Listen(Options.QueueLength);
        }

        public async Task<SocketWorker> Accept()
        {
            while (true)
            {
                try
                {
                    var socket = await listeningSocket.AcceptAsync();
                    return new SocketWorker(socket, Options);
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
            }
        }

        public override void Dispose()
        {
            listeningSocket.Dispose();
        }
    }
}
