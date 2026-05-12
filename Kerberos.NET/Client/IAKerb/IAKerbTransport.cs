// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using Kerberos.NET.Transport;

namespace Kerberos.NET.Client
{
    /// <summary>
    /// Represents a single KDC message exchange captured by the IAKerb transport.
    /// Contains the domain/realm, the outgoing request bytes, and a completion source
    /// for the response that will be provided by the IAKerb initiator.
    /// </summary>
    internal class IAKerbExchange
    {
        public string Domain { get; }

        public ReadOnlyMemory<byte> Request { get; }

        public TaskCompletionSource<ReadOnlyMemory<byte>> ResponseSource { get; }

        public IAKerbExchange(string domain, ReadOnlyMemory<byte> request)
        {
            this.Domain = domain;
            this.Request = request;
            this.ResponseSource = new TaskCompletionSource<ReadOnlyMemory<byte>>(
                TaskCreationOptions.RunContinuationsAsynchronously
            );
        }
    }

    /// <summary>
    /// A custom Kerberos transport that bridges between the KerberosClient's
    /// async message flow and the step-by-step IAKerb token exchange.
    ///
    /// When the KerberosClient calls SendMessage, this transport captures the
    /// request and waits for the IAKerb initiator to provide a response.
    /// Supports multiple sequential exchanges (pre-auth retries, referrals).
    /// </summary>
    internal class IAKerbTransport : KerberosTransportBase
    {
        private readonly ConcurrentQueue<IAKerbExchange> exchanges = new ConcurrentQueue<IAKerbExchange>();
        private readonly SemaphoreSlim exchangeReady = new SemaphoreSlim(0);

        public IAKerbTransport()
            : base(null)
        {
            this.Enabled = true;
        }

        public override async Task<ReadOnlyMemory<byte>> SendMessage(
            string domain,
            ReadOnlyMemory<byte> req,
            CancellationToken cancellation = default
        )
        {
            var exchange = new IAKerbExchange(domain, req);

            // Enqueue the exchange and signal the initiator
            this.exchanges.Enqueue(exchange);
            this.exchangeReady.Release();

            // Wait for the IAKerb initiator to provide the KDC response
            using var registration = cancellation.Register(
                () => exchange.ResponseSource.TrySetCanceled(cancellation)
            );

            return await exchange.ResponseSource.Task.ConfigureAwait(false);
        }

        /// <summary>
        /// Gets the next pending exchange from the KerberosClient.
        /// Called by the IAKerb initiator to retrieve outgoing KDC requests.
        /// </summary>
        internal async Task<IAKerbExchange> GetNextExchangeAsync(CancellationToken cancellation = default)
        {
            await this.exchangeReady.WaitAsync(cancellation).ConfigureAwait(false);

            this.exchanges.TryDequeue(out var exchange);

            return exchange;
        }
    }
}
