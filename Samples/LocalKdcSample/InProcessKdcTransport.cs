// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Threading;
using System.Threading.Tasks;
using Kerberos.NET.Server;
using Kerberos.NET.Transport;

namespace LocalKdcSample
{
    /// <summary>
    /// A Kerberos transport that delivers KDC messages straight to an in-proc <see cref="KdcServer"/>
    /// by calling <see cref="KdcServer.ProcessMessage"/> - no sockets, no network, no off-box KDC.
    ///
    /// The IAKerb acceptor uses this transport to "forward" the AS/TGS messages it receives from the
    /// client. Because the KDC is running in the same process, the forward is just a method call.
    /// </summary>
    internal class InProcessKdcTransport : KerberosTransportBase
    {
        private readonly KdcServer kdc;

        public InProcessKdcTransport(KdcServer kdc)
            : base(null)
        {
            this.kdc = kdc;
            this.Enabled = true;
        }

        public override Task<ReadOnlyMemory<byte>> SendMessage(
            string domain,
            ReadOnlyMemory<byte> req,
            CancellationToken cancellation = default
        )
        {
            // The local KDC serves a single realm, so the requested domain is ignored.
            return this.kdc.ProcessMessage(req);
        }
    }
}
