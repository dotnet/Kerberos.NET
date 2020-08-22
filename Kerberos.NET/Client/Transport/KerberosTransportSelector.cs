// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Kerberos.NET.Transport
{
    public class KerberosTransportSelector : KerberosTransportBase
    {
        public KerberosTransportSelector(IEnumerable<IKerberosTransport> transports)
        {
            this.Transports = transports;
        }

        public IEnumerable<IKerberosTransport> Transports { get; }

        public override async Task<T> SendMessage<T>(
            string domain,
            ReadOnlyMemory<byte> encoded,
            CancellationToken cancellation = default
        )
        {
            // basic logic should be
            // foreach transport
            // if (canSendMessage) { trySend }
            // if try = fail for transport reasons move on to next
            // if try = fail or protocol reasons, throw and bail

            foreach (var transport in this.Transports.Where(t => t.Enabled && !t.TransportFailed))
            {
                transport.MaximumAttempts = this.MaximumAttempts;
                transport.ConnectTimeout = this.ConnectTimeout;
                transport.SendTimeout = this.SendTimeout;
                transport.ReceiveTimeout = this.ReceiveTimeout;

                try
                {
                    return await transport.SendMessage<T>(domain, encoded, cancellation).ConfigureAwait(true);
                }
                catch (KerberosTransportException tex)
                {
                    transport.TransportFailed = true;
                    transport.LastError = this.LastError = tex;
                }
            }

            throw this.LastError ?? new KerberosTransportException("No transport could be used to send the message");
        }

        protected override void Dispose(bool disposing)
        {
            foreach (var transport in this.Transports)
            {
                if (transport is IDisposable disposable)
                {
                    disposable.Dispose();
                }
            }

            base.Dispose(disposing);
        }
    }
}