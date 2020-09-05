// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Kerberos.NET.Configuration;
using Microsoft.Extensions.Logging;

namespace Kerberos.NET.Transport
{
    public class KerberosTransportSelector : KerberosTransportBase
    {
        private readonly ILogger logger;
        private readonly Krb5Config config;

        public KerberosTransportSelector(IEnumerable<IKerberosTransport> transports, Krb5Config config, ILoggerFactory logger)
            : base(logger)
        {
            if (transports == null)
            {
                throw new ArgumentNullException(nameof(transports));
            }

            if (config == null)
            {
                throw new ArgumentNullException(nameof(config));
            }

            this.logger = logger.CreateLoggerSafe<KerberosTransportSelector>();

            this.Transports = transports;
            this.config = config;
        }

        public IEnumerable<IKerberosTransport> Transports { get; }

        public override async Task<T> SendMessage<T>(
            string domain,
            ReadOnlyMemory<byte> encoded,
            CancellationToken cancellation = default
        )
        {
            // old logic is:
            // foreach transport
            // if (canSendMessage) { trySend }
            // if try = fail for transport reasons move on to next
            // if try = fail or protocol reasons, throw and bail

            var exceptions = new List<Exception>();

            foreach (var transport in this.Transports.Where(t => t.Enabled))
            {
                transport.MaximumAttempts = this.MaximumAttempts;
                transport.ConnectTimeout = this.ConnectTimeout;
                transport.SendTimeout = this.SendTimeout;
                transport.ReceiveTimeout = this.ReceiveTimeout;
                transport.Configuration = this.config;

                if (transport is KerberosTransportBase kerbTransport)
                {
                    kerbTransport.ScopeId = this.ScopeId;
                }

                try
                {
                    return await transport.SendMessage<T>(domain, encoded, cancellation).ConfigureAwait(true);
                }
                catch (KerberosTransportException tex)
                {
                    exceptions.Add(tex);

                    transport.TransportFailed = true;
                    transport.LastError = this.LastError = tex;

                    this.logger.LogDebug("Transport {Transport} failed connecting to {Domain} so moving on to next transporter", transport.GetType().Name, domain);
                }
            }

            if (exceptions.Any())
            {
                throw new AggregateException(exceptions);
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
