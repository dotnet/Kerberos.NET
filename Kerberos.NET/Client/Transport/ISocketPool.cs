// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Threading.Tasks;
using Kerberos.NET.Dns;

namespace Kerberos.NET.Client
{
    public interface ISocketPool : IDisposable
    {
        int MaxPoolSize { get; set; }

        TimeSpan ScavengeWindow { get; set; }

        Task<ITcpSocket> Request(DnsRecord target, TimeSpan connectTimeout);
    }
}