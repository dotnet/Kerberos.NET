using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace Kerberos.NET.Server
{
    public class KdcListenerOptions
    {
        public EndPoint ListeningOn { get; set; }

        public bool SupportTcp { get; set; } = true;

        public bool SupportUdp { get; set; } = false;

        public int QueueLength { get; set; } = 1000;

        public TimeSpan ReceiveTimeout { get; set; } = TimeSpan.FromSeconds(30);

        public int MaxReadBufferSize { get; set; } = 1024 * 1024;

        public int MaxWriteBufferSize { get; set; } = 64 * 1024;

        public ILogger Log { get; set; }

        public string DefaultRealm { get; set; }

        public bool IsDebug { get; set; }

        public Func<string, Task<IRealmService>> RealmLocator { get; set; }
    }

    public class KdcServiceListener : IDisposable
    {
        /*
             - spin up UDP+TCP sockets
             - on Accept => dispatch to handler
             - on handler => parse length, then read in message
             - on message => decode type, pass to kdc
         */

        private readonly KdcListenerOptions options;

        private readonly SocketListener tcpSocketListener;
        //private readonly SocketListener udpSocketListener;

        private readonly TaskCompletionSource<object> startTcs
            = new TaskCompletionSource<object>(TaskCreationOptions.RunContinuationsAsynchronously);

        public KdcServiceListener(KdcListenerOptions options)
        {
            this.options = options;

            if (options.SupportTcp)
            {
                tcpSocketListener = new SocketListener(options);
            }
        }

        public Task Start()
        {
            if (tcpSocketListener != null)
            {
                ThreadPool.QueueUserWorkItem(StartListenerThreads, tcpSocketListener, preferLocal: false);
            }

            //if (udpSocketListener != null)
            //{
            //    ThreadPool.QueueUserWorkItem(StartListenerThreads, udpSocketListener, preferLocal: false);
            //}

            return startTcs.Task;
        }

        private void StartListenerThreads(SocketListener listener)
        {
            _ = AcceptConnections(listener);
        }

        private async Task AcceptConnections(SocketListener socketListener)
        {
            if (socketListener == null)
            {
                return;
            }

            try
            {
                while (true)
                {
                    var worker = await socketListener.Accept();

                    if (worker == null)
                    {
                        break;
                    }

                    _ = worker.HandleMessage();
                }
            }
            catch (Exception ex)
            {
                Log(ex);
            }
            finally
            {
                socketListener.Dispose();
                startTcs.TrySetResult(null);
            }
        }

        private void Log(Exception ex)
        {
            if (options.Log != null)
            {
                options.Log.WriteLine(KerberosLogSource.ServiceListener, ex);
            }
        }

        public void Dispose()
        {
            if (tcpSocketListener != null)
            {
                tcpSocketListener.Dispose();
            }
        }
    }
}
