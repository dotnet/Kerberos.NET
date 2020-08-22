// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Threading.Tasks;
using Kerberos.NET.Server;

namespace Tests.Kerberos.NET
{
    internal class TcpKdcListener : IDisposable
    {
        private readonly KdcServiceListener server;

        public TcpKdcListener(KdcServiceListener server)
        {
            this.server = server;
        }

        public void Dispose()
        {
            this.server.Stop();
            this.server.Dispose();
        }

        public Task Start()
        {
            return this.server.Start();
        }
    }
}