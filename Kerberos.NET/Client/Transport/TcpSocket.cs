// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Kerberos.NET.Dns;

namespace Kerberos.NET.Client
{
    internal class TcpSocket : ITcpSocket
    {
        private readonly NamedPool pool;
        private readonly TcpClient client;

        public string TargetName { get; private set; }

        public TimeSpan ReceiveTimeout
        {
            get => TimeSpan.FromMilliseconds(this.client.ReceiveTimeout);
            set => this.client.ReceiveTimeout = (int)value.TotalMilliseconds;
        }

        public TimeSpan SendTimeout
        {
            get => TimeSpan.FromMilliseconds(this.client.SendTimeout);
            set => this.client.SendTimeout = (int)value.TotalMilliseconds;
        }

        public bool Connected => this.client.Connected;

        public DateTimeOffset LastRelease { get; private set; }

        public TcpSocket(NamedPool pool)
        {
            this.pool = pool;

            this.client = new TcpClient(AddressFamily.InterNetwork)
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
                var connectTask = this.client.ConnectAsync(target.Target, target.Port);

                using (cts.Token.Register(() => tcs.TrySetResult(true)))
                {
                    if (connectTask != await Task.WhenAny(connectTask, tcs.Task).ConfigureAwait(true))
                    {
                        return false;
                    }

                    if (connectTask.Exception?.InnerException != null)
                    {
                        throw connectTask.Exception.InnerException;
                    }
                }
            }

            this.TargetName = target.Target;

            return true;
        }

        public void Free()
        {
            this.client.Dispose();
        }

        public void Dispose()
        {
            this.pool.Release(this);

            this.LastRelease = DateTimeOffset.UtcNow;
        }

        public NetworkStream GetStream()
        {
            return this.client.GetStream();
        }
    }
}