// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Net.Sockets;
using System.Threading.Tasks;
using Kerberos.NET.Dns;

namespace Kerberos.NET.Client
{
    public interface ITcpSocket : IDisposable
    {
        bool Connected { get; }

        DateTimeOffset LastRelease { get; }

        TimeSpan ReceiveTimeout { get; set; }

        TimeSpan SendTimeout { get; set; }

        string TargetName { get; }

        Task<bool> Connect(DnsRecord target, TimeSpan connectTimeout);

        void Free();

        NetworkStream GetStream();
    }
}