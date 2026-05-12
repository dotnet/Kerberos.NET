// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Kerberos.NET.Configuration;
using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;

namespace Kerberos.NET.Client
{
    /// <summary>
    /// The current state of the IAKerb initiator context.
    /// </summary>
    public enum IAKerbInitiatorState
    {
        /// <summary>
        /// Context has not started.
        /// </summary>
        NotStarted,

        /// <summary>
        /// The client is exchanging KDC messages through the proxy.
        /// </summary>
        InProgress,

        /// <summary>
        /// Context establishment is complete.
        /// </summary>
        Complete,

        /// <summary>
        /// Context establishment failed.
        /// </summary>
        Failed
    }

    /// <summary>
    /// IAKerb client-side initiator. Wraps a KerberosClient with an IAKerb transport
    /// to produce IAKERB_PROXY GSS tokens instead of communicating directly with the KDC.
    ///
    /// Usage:
    /// <code>
    /// var initiator = new IAKerbInitiator(credential, spn);
    /// var result = await initiator.InitSecurityContext();
    /// while (result.ContinueNeeded)
    /// {
    ///     var serverToken = SendToServer(result.Token); // application-specific
    ///     result = await initiator.InitSecurityContext(serverToken);
    /// }
    /// // result.Token is the final AP-REQ; result.SessionContext has the session keys
    /// </code>
    /// </summary>
    public class IAKerbInitiator : IDisposable
    {
        private static readonly Oid IAKerbOid = new(MechType.IAKerb);

        private readonly KerberosClient client;
        private readonly IAKerbTransport transport;
        private readonly KerberosCredential credential;
        private readonly string servicePrincipalName;
        private readonly MemoryStream transcript = new();

        private Task authenticateTask;
        private Task<ApplicationSessionContext> serviceTicketTask;
        private ReadOnlyMemory<byte>? cookie;
        private bool disposed;

        /// <summary>
        /// The current state of the initiator.
        /// </summary>
        public IAKerbInitiatorState State { get; private set; } = IAKerbInitiatorState.NotStarted;

        /// <summary>
        /// The AP options to use when creating the final AP-REQ.
        /// </summary>
        public ApOptions ApOptions { get; set; } = ApOptions.MutualRequired;

        /// <summary>
        /// The GSS context flags to use for the security context.
        /// </summary>
        public GssContextEstablishmentFlag GssContextFlags { get; set; } =
            GssContextEstablishmentFlag.GSS_C_REPLAY_FLAG |
            GssContextEstablishmentFlag.GSS_C_SEQUENCE_FLAG |
            GssContextEstablishmentFlag.GSS_C_CONF_FLAG |
            GssContextEstablishmentFlag.GSS_C_INTEG_FLAG |
            GssContextEstablishmentFlag.GSS_C_EXTENDED_ERROR_FLAG;

        /// <summary>
        /// The session context after successful authentication.
        /// Only available when <see cref="State"/> is <see cref="IAKerbInitiatorState.Complete"/>.
        /// </summary>
        public ApplicationSessionContext SessionContext { get; private set; }

        /// <summary>
        /// Creates a new IAKerb initiator that will authenticate using the given credential
        /// and request a service ticket for the specified SPN.
        /// </summary>
        /// <param name="credential">The credential to authenticate with.</param>
        /// <param name="servicePrincipalName">The SPN of the target service.</param>
        /// <param name="config">Optional Kerberos configuration.</param>
        public IAKerbInitiator(
            KerberosCredential credential,
            string servicePrincipalName,
            Krb5Config config = null
        )
        {
            this.credential = credential ?? throw new ArgumentNullException(nameof(credential));
            this.servicePrincipalName = servicePrincipalName ?? throw new ArgumentNullException(nameof(servicePrincipalName));

            this.transport = new IAKerbTransport();
            this.client = new KerberosClient(config, transports: this.transport);
        }

        /// <summary>
        /// Performs one step of the IAKerb GSS-API context establishment.
        /// Call with null inputToken for the first call, then with the server's response token for subsequent calls.
        /// </summary>
        /// <param name="inputToken">The GSS token received from the server, or null for the first call.</param>
        /// <param name="cancellation">Cancellation token.</param>
        /// <returns>
        /// A tuple of (outputToken, continueNeeded).
        /// Send outputToken to the server. If continueNeeded is false, authentication is complete.
        /// </returns>
        public async Task<IAKerbContextResult> InitSecurityContext(
            ReadOnlyMemory<byte>? inputToken = null,
            CancellationToken cancellation = default
        )
        {
            try
            {
                return await InitSecurityContextCore(inputToken, cancellation).ConfigureAwait(false);
            }
            catch
            {
                this.State = IAKerbInitiatorState.Failed;
                throw;
            }
        }

        private IAKerbExchange currentExchange;
        private Task<IAKerbExchange> pendingExchangeTask;

        private async Task<IAKerbContextResult> InitSecurityContextCore(
            ReadOnlyMemory<byte>? inputToken,
            CancellationToken cancellation
        )
        {
            // Phase 1: Feed the server's response back to the transport
            if (inputToken.HasValue)
            {
                var gssToken = GssApiToken.Decode(inputToken.Value);
                var iakerb = new IAKerbContextToken(gssToken);

                this.cookie = iakerb.Header.Cookie;

                // Record in transcript (exact wire bytes)
                var inputBytes = inputToken.Value.ToArray();
                this.transcript.Write(inputBytes, 0, inputBytes.Length);

                // Provide the KDC response to the transport (unblocks KerberosClient)
                if (iakerb.Body.Length > 0)
                {
                    this.currentExchange.ResponseSource.SetResult(iakerb.Body);
                }
            }

            // Phase 2: Start or advance the Kerberos flow
            if (this.State == IAKerbInitiatorState.NotStarted)
            {
                this.authenticateTask = this.client.Authenticate(this.credential);
                this.State = IAKerbInitiatorState.InProgress;
            }

            // Phase 3: Wait for either the active task to complete or a new exchange
            return await WaitForNextAction(cancellation).ConfigureAwait(false);
        }

        private async Task<IAKerbContextResult> WaitForNextAction(
            CancellationToken cancellation
        )
        {
            // Only create a new exchange task when the previous one was consumed (set to null).
            // A completed but unconsumed task holds a valid exchange result that must not be discarded.
            if (this.pendingExchangeTask == null)
            {
                this.pendingExchangeTask = this.transport.GetNextExchangeAsync(cancellation);
            }

            // Determine which task is currently active
            Task activeTask = (Task)this.authenticateTask ?? this.serviceTicketTask;

            if (activeTask != null)
            {
                var winner = await Task.WhenAny(activeTask, this.pendingExchangeTask).ConfigureAwait(false);

                if (winner == activeTask)
                {
                    if (activeTask == this.authenticateTask)
                    {
                        await this.authenticateTask.ConfigureAwait(false); // propagate exceptions
                        this.authenticateTask = null;

                        // Start service ticket request
                        // IAKerb requires a subkey (for GSS_EXTS_FINISHED), which is generated
                        // when MutualRequired is set. Enforce this regardless of caller's ApOptions.
                        var apOptions = this.ApOptions | ApOptions.MutualRequired;

                        this.serviceTicketTask = this.client.GetServiceTicket(
                            new RequestServiceTicket
                            {
                                ServicePrincipalName = this.servicePrincipalName,
                                ApOptions = apOptions,
                                GssContextFlags = this.GssContextFlags,
                                DelegationInfoModifier = this.InjectFinishedExtension
                            },
                            cancellation
                        );

                        // Recurse - GetServiceTicket may produce a new exchange
                        // The existing pendingExchangeTask will capture it
                        return await WaitForNextAction(cancellation).ConfigureAwait(false);
                    }

                    if (activeTask == this.serviceTicketTask)
                    {
                        this.SessionContext = await this.serviceTicketTask.ConfigureAwait(false);
                        this.State = IAKerbInitiatorState.Complete;

                        var apReqBytes = GssApiToken.Encode(IAKerbOid, this.SessionContext.ApReq);
                        return new IAKerbContextResult(apReqBytes, continueNeeded: false, this.SessionContext);
                    }
                }
            }

            // An exchange is ready - wrap it in an IAKERB_PROXY token
            this.currentExchange = await this.pendingExchangeTask.ConfigureAwait(false);
            this.pendingExchangeTask = null;

            var header = new IAKerbHeader
            {
                TargetRealm = this.currentExchange.Domain,
                Cookie = this.cookie
            };

            var outputToken = GssApiToken.EncodeIAKerbProxy(header, this.currentExchange.Request);

            // Record in transcript (exact wire bytes)
            var outputBytes = outputToken.ToArray();
            this.transcript.Write(outputBytes, 0, outputBytes.Length);

            return new IAKerbContextResult(outputToken, continueNeeded: true);
        }

        private void InjectFinishedExtension(DelegationInfo delegationInfo, KrbEncryptionKey subkey)
        {
            if (delegationInfo == null)
            {
                return;
            }

            if (subkey == null)
            {
                throw new InvalidOperationException(
                    "IAKerb requires an authenticator subkey for GSS_EXTS_FINISHED, but none was generated.");
            }

            // Compute the FINISHED checksum over the transcript of all preceding GSS tokens
            var transcriptBytes = this.transcript.ToArray();
            var finished = KrbFinished.Create(transcriptBytes, subkey.AsKey());

            // Encode as a GSS-API CFX extension
            var finishedEncoded = finished.Encode();
            var extensionEncoded = GssApiCfxExtensions.Encode(KrbFinished.GssExtsFinishedType, finishedEncoded);

            delegationInfo.Extensions = extensionEncoded;
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!this.disposed)
            {
                if (disposing)
                {
                    this.client?.Dispose();
                    this.transcript?.Dispose();
                }

                this.disposed = true;
            }
        }

        public void Dispose()
        {
            this.Dispose(true);
            GC.SuppressFinalize(this);
        }
    }
}
