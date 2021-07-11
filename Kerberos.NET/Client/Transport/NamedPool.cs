// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using Kerberos.NET.Dns;

namespace Kerberos.NET.Client
{
    internal class NamedPool : IDisposable
    {
        private readonly DnsRecord target;

        private int activeConnections;

        public NamedPool(DnsRecord target)
        {
            this.target = target;
        }

        public ConcurrentQueue<TcpSocket> Queue { get; set; } = new ConcurrentQueue<TcpSocket>();

        public int ActiveConnections => this.activeConnections;

        public int IdleConnections => this.Queue.Count;

        public int MaxPoolSize { get; set; }

        public void Poll(TimeSpan window)
        {
#pragma warning disable CA2000 // Dispose objects before losing scope
            if (this.Queue.TryPeek(out TcpSocket socket) && socket.LastRelease.Add(window) <= DateTimeOffset.UtcNow)
            {
                if (this.Queue.TryDequeue(out socket))
                {
                    socket.Free();
                    Interlocked.Decrement(ref this.activeConnections);
                }
            }
#pragma warning restore CA2000 // Dispose objects before losing scope
        }

        public async Task<TcpSocket> OpenSocket(TimeSpan connectTimeout)
        {
            bool connected = false;

            Interlocked.Increment(ref this.activeConnections);

            try
            {
                if (this.activeConnections > this.MaxPoolSize)
                {
                    throw new InvalidOperationException($"Connection pool maxed out at {this.ActiveConnections} connections.");
                }

#pragma warning disable CA2000 // Dispose objects before losing scope
                var client = new TcpSocket(this);
#pragma warning restore CA2000 // Dispose objects before losing scope

                connected = await client.Connect(this.target, connectTimeout).ConfigureAwait(false);

                if (connected)
                {
                    return client;
                }
            }
            finally
            {
                if (!connected)
                {
                    Interlocked.Decrement(ref this.activeConnections);
                }
            }

            return null;
        }

        public void Release(TcpSocket socket)
        {
            if (!socket.Connected)
            {
                socket.Free();

                Interlocked.Decrement(ref this.activeConnections);

                return;
            }

            this.Queue.Enqueue(socket);
        }

        public void Dispose()
        {
            while (this.Queue.Count > 0)
            {
#pragma warning disable CA2000 // Dispose objects before losing scope
                if (this.Queue.TryDequeue(out TcpSocket socket))
                {
                    socket.Free();
                }
#pragma warning restore CA2000 // Dispose objects before losing scope
            }
        }
    }
}
