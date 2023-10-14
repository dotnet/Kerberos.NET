// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Threading;
using System.Threading.Tasks;
using Kerberos.NET.Transport;

namespace Tests.Kerberos.NET
{
    internal class InMemoryTransport : KerberosTransportBase
    {
        private readonly KdcListener listener;

        public InMemoryTransport(KdcListener listener)
            : base(null)
        {
            this.listener = listener;
            this.Enabled = true;
        }

        public override async Task<ReadOnlyMemory<byte>> SendMessage(
            string domain,
            ReadOnlyMemory<byte> req,
            CancellationToken cancellation = default
        )
        {
            var response = await this.listener.Receive(req);

            return response;
        }
    }
}
