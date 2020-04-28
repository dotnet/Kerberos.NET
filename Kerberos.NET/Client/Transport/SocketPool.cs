using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Kerberos.NET.Dns;

namespace Kerberos.NET.Client
{
    internal class SocketPool : ISocketPool
    {
        private readonly ConcurrentDictionary<string, NamedPool> pool
            = new ConcurrentDictionary<string, NamedPool>();

        private readonly Task backgroundWorker;
        private readonly CancellationTokenSource cts;

        public SocketPool()
        {
            cts = new CancellationTokenSource();

            backgroundWorker = Task.Run(() => PollPool(), cts.Token);
        }

        public int MaxPoolSize { get; set; } = 10;

        public TimeSpan ScavengeWindow { get; set; } = TimeSpan.FromSeconds(30);

        public async Task<ITcpSocket> Request(DnsRecord target, TimeSpan connectTimeout)
        {
            if (!pool.TryGetValue(target.Address, out NamedPool queue))
            {
                queue = new NamedPool(target) { MaxPoolSize = MaxPoolSize };

                pool.TryAdd(target.Address, queue);
            }

            if (queue.Queue.TryDequeue(out TcpSocket client))
            {
                return client;
            }

            return await queue.OpenSocket(connectTimeout);
        }

        private async Task PollPool()
        {
            while (!cts.Token.IsCancellationRequested)
            {
                foreach (var key in pool.Keys.ToList())
                {
                    var queue = pool[key];

                    queue.Poll(ScavengeWindow);
                }

                await Task.Delay(ScavengeWindow, cts.Token);
            }
        }

        public void Dispose()
        {
            cts.Cancel();
            cts.Dispose();
            backgroundWorker.ContinueWith(t => t.Dispose());

            foreach (var key in pool.Keys.ToList())
            {
                var queue = pool[key];

                queue.Dispose();
            }
        }
    }

    internal class NamedPool : IDisposable
    {
        private int activeConnections;

        private readonly DnsRecord target;

        public NamedPool(DnsRecord target)
        {
            this.target = target;
        }

        public ConcurrentQueue<TcpSocket> Queue { get; set; } = new ConcurrentQueue<TcpSocket>();

        public int ActiveConnections => activeConnections;

        public int IdleConnections => Queue.Count;

        public int MaxPoolSize { get; set; }

        public void Poll(TimeSpan window)
        {
            if (Queue.TryPeek(out TcpSocket socket) && socket.LastRelease.Add(window) <= DateTimeOffset.UtcNow)
            {
                if (Queue.TryDequeue(out socket))
                {
                    socket.Free();
                    Interlocked.Decrement(ref activeConnections);
                }
            }
        }

        public async Task<TcpSocket> OpenSocket(TimeSpan connectTimeout)
        {
            bool connected = false;

            Interlocked.Increment(ref activeConnections);

            try
            {
                if (activeConnections > MaxPoolSize)
                {
                    throw new InvalidOperationException($"Connection pool maxed out at {ActiveConnections} connections.");
                }

                var client = new TcpSocket(this);

                connected = await client.Connect(target, connectTimeout);

                if (connected)
                {
                    return client;
                }
            }
            finally
            {
                if (!connected)
                {
                    Interlocked.Decrement(ref activeConnections);
                }
            }

            return null;
        }

        public void Release(TcpSocket socket)
        {
            if (!socket.Connected)
            {
                socket.Free();

                Interlocked.Decrement(ref activeConnections);

                return;
            }

            Queue.Enqueue(socket);
        }

        public void Dispose()
        {
            while (Queue.Count > 0)
            {
                if (Queue.TryDequeue(out TcpSocket socket))
                {
                    socket.Free();
                }
            }
        }
    }

    internal class TcpSocket : ITcpSocket
    {
        private readonly NamedPool pool;
        private readonly TcpClient client;

        public string TargetName { get; private set; }

        public TimeSpan ReceiveTimeout
        {
            get => TimeSpan.FromMilliseconds(client.ReceiveTimeout);
            set => client.ReceiveTimeout = (int)value.TotalMilliseconds;
        }

        public TimeSpan SendTimeout
        {
            get => TimeSpan.FromMilliseconds(client.SendTimeout);
            set => client.SendTimeout = (int)value.TotalMilliseconds;
        }

        public bool Connected => client.Connected;

        public DateTimeOffset LastRelease { get; private set; }

        public TcpSocket(NamedPool pool)
        {
            this.pool = pool;

            client = new TcpClient(AddressFamily.InterNetwork)
            {
                NoDelay = true,
                LingerState = new LingerOption(false, 0)
            };
        }

        public async Task<bool> Connect(DnsRecord target, TimeSpan connectTimeout)
        {
            var tcs = new TaskCompletionSource<bool>();

            using (var cts = new CancellationTokenSource(connectTimeout))
            {
                var connectTask = client.ConnectAsync(target.Target, target.Port);

                using (cts.Token.Register(() => tcs.TrySetResult(true)))
                {
                    if (connectTask != await Task.WhenAny(connectTask, tcs.Task))
                    {
                        return false;
                    }

                    if (connectTask.Exception?.InnerException != null)
                    {
                        throw connectTask.Exception.InnerException;
                    }
                }
            }

            TargetName = target.Target;

            return true;
        }

        public void Free()
        {
            client.Dispose();
        }

        public void Dispose()
        {
            pool.Release(this);

            LastRelease = DateTimeOffset.UtcNow;
        }

        public NetworkStream GetStream()
        {
            return client.GetStream();
        }
    }
}
