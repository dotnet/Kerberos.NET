﻿using System;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace Kerberos.NET.Server
{
    internal class SocketListener : SocketBase
    {
        private readonly Socket listeningSocket;

        private readonly Func<Socket, ListenerOptions, SocketWorker> workerFunc;

        public SocketListener(ListenerOptions options, Func<Socket, ListenerOptions, SocketWorker> workerFunc)
            : base(options)
        {
            listeningSocket = new Socket(SocketType.Stream, ProtocolType.Tcp);

            listeningSocket.Bind(Options.ListeningOn);
            listeningSocket.Listen(Options.QueueLength);

            this.workerFunc = workerFunc;
        }

        public async Task<SocketWorker> Accept()
        {
            while (true)
            {
                try
                {
                    var socket = await listeningSocket.AcceptAsync();

                    return workerFunc(socket, Options);
                }
                catch (SocketException sx) when (IsSocketAbort(sx.SocketErrorCode) || IsSocketError(sx.SocketErrorCode))
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
