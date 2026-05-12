// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Transport;
using Microsoft.Extensions.Logging;

namespace Kerberos.NET.Server
{
    /// <summary>
    /// The current state of the IAKerb acceptor context.
    /// </summary>
    public enum IAKerbAcceptorState
    {
        /// <summary>
        /// Waiting for the first IAKerb token.
        /// </summary>
        WaitingForToken,

        /// <summary>
        /// Proxying KDC messages.
        /// </summary>
        Proxying,

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
    /// IAKerb server-side acceptor/proxy. Receives IAKERB_PROXY tokens from the client,
    /// forwards the contained Kerberos messages to the KDC, and wraps responses back.
    /// When the client sends the final AP-REQ, validates the GSS_EXTS_FINISHED checksum
    /// and completes authentication.
    ///
    /// Usage:
    /// <code>
    /// var acceptor = new IAKerbAcceptor(kdcTransport, serviceKeys);
    /// while (true)
    /// {
    ///     var clientToken = ReceiveFromClient(); // application-specific
    ///     var result = await acceptor.AcceptSecurityContext(clientToken);
    ///     if (result.IsComplete)
    ///     {
    ///         // Authentication complete - result.DecryptedApReq has the identity
    ///         if (result.Token.HasValue) SendToClient(result.Token.Value); // AP-REP
    ///         break;
    ///     }
    ///     SendToClient(result.Token.Value); // proxy response
    /// }
    /// </code>
    /// </summary>
    public class IAKerbAcceptor : IDisposable
    {
        private static readonly Oid IAKerbOid = new(MechType.IAKerb);

        private readonly IKerberosTransport kdcTransport;
        private readonly KeyTable serviceKeys;
        private readonly MemoryStream transcript = new();
        private readonly ILogger logger;
        private bool disposed;

        /// <summary>
        /// The current state of the acceptor.
        /// </summary>
        public IAKerbAcceptorState State { get; private set; } = IAKerbAcceptorState.WaitingForToken;

        /// <summary>
        /// The decrypted AP-REQ after successful authentication.
        /// </summary>
        public DecryptedKrbApReq DecryptedApReq { get; private set; }

        /// <summary>
        /// Creates a new IAKerb acceptor that uses the given transport to forward messages to the KDC.
        /// </summary>
        /// <param name="kdcTransport">Transport to communicate with the real KDC.</param>
        /// <param name="serviceKeys">The service's keytab for decrypting the final AP-REQ.</param>
        /// <param name="logger">Optional logger factory.</param>
        public IAKerbAcceptor(
            IKerberosTransport kdcTransport,
            KeyTable serviceKeys,
            ILoggerFactory logger = null
        )
        {
            this.kdcTransport = kdcTransport ?? throw new ArgumentNullException(nameof(kdcTransport));
            this.serviceKeys = serviceKeys ?? throw new ArgumentNullException(nameof(serviceKeys));
            this.logger = logger.CreateLoggerSafe<IAKerbAcceptor>();
        }

        /// <summary>
        /// Processes an incoming GSS token from the IAKerb initiator.
        /// </summary>
        /// <param name="inputToken">The GSS token from the client.</param>
        /// <param name="cancellation">Cancellation token.</param>
        /// <returns>
        /// An <see cref="IAKerbAcceptorResult"/> describing the next action.
        /// If <see cref="IAKerbAcceptorResult.IsComplete"/> is false, send <see cref="IAKerbAcceptorResult.Token"/>
        /// to the client and continue. If true, authentication succeeded and
        /// <see cref="IAKerbAcceptorResult.DecryptedApReq"/> contains the authenticated identity.
        /// </returns>
        public async Task<IAKerbAcceptorResult> AcceptSecurityContext(
            ReadOnlyMemory<byte> inputToken,
            CancellationToken cancellation = default
        )
        {
            try
            {
                return await AcceptSecurityContextCore(inputToken, cancellation).ConfigureAwait(false);
            }
            catch
            {
                this.State = IAKerbAcceptorState.Failed;
                throw;
            }
        }

        private async Task<IAKerbAcceptorResult> AcceptSecurityContextCore(
            ReadOnlyMemory<byte> inputToken,
            CancellationToken cancellation
        )
        {
            var gssToken = GssApiToken.Decode(inputToken);

            if (gssToken.ThisMech.Value == MechType.IAKerb &&
                gssToken.MessageType == MessageType.IAKERB_HEADER)
            {
                return await HandleIAKerbProxy(inputToken, gssToken, cancellation).ConfigureAwait(false);
            }

            if (gssToken.ThisMech.Value == MechType.IAKerb &&
                gssToken.MessageType == MessageType.KRB_AP_REQ)
            {
                return HandleApReq(inputToken, gssToken);
            }

            throw new KerberosProtocolException(
                KerberosErrorCode.KRB_ERR_GENERIC,
                $"Unexpected IAKerb token type: mech={gssToken.ThisMech.Value}, msgType={gssToken.MessageType}"
            );
        }

        private async Task<IAKerbAcceptorResult> HandleIAKerbProxy(
            ReadOnlyMemory<byte> inputToken,
            GssApiToken gssToken,
            CancellationToken cancellation
        )
        {
            var iakerb = new IAKerbContextToken(gssToken);
            var targetRealm = iakerb.Header.TargetRealm;

            this.State = IAKerbAcceptorState.Proxying;

            // Record input token in transcript
            this.transcript.Write(inputToken.ToArray(), 0, inputToken.Length);

            if (iakerb.Body.Length == 0)
            {
                // Empty body = realm query (Section 3.1)
                var realmHeader = new IAKerbHeader { TargetRealm = targetRealm };
                var realmResponse = GssApiToken.EncodeIAKerbProxy(realmHeader, ReadOnlyMemory<byte>.Empty);
                this.transcript.Write(realmResponse.ToArray(), 0, realmResponse.Length);
                return new IAKerbAcceptorResult(realmResponse, isComplete: false);
            }

            // Forward the Kerberos message to the KDC using raw transport
            ReadOnlyMemory<byte> kdcResponse;

            try
            {
                if (this.kdcTransport is IKerberosTransport2 transport2)
                {
                    kdcResponse = await transport2.SendMessage(
                        targetRealm,
                        iakerb.Body,
                        cancellation
                    ).ConfigureAwait(false);
                }
                else
                {
                    // Fall back to typed send - try AS-REP first, then TGS-REP
                    kdcResponse = await SendRawMessage(targetRealm, iakerb.Body, cancellation).ConfigureAwait(false);
                }
            }
            catch (KerberosTransportException ex) when (ex.Error == null)
            {
                // Could not reach KDC - generate IAKerb-specific error
                this.logger.LogWarning(ex, "IAKerb proxy could not reach KDC for realm {Realm}", targetRealm);

                var error = new KrbError
                {
                    ErrorCode = KerberosErrorCode.KRB_AP_ERR_IAKERB_KDC_NO_RESPONSE,
                    EText = "The KDC did not respond to the IAKERB proxy",
                    Realm = targetRealm,
                    SName = KrbPrincipalName.FromString($"krbtgt/{targetRealm}")
                };

                kdcResponse = error.EncodeApplication();
            }

            // Wrap the KDC response in IAKERB_PROXY
            var responseHeader = new IAKerbHeader
            {
                TargetRealm = targetRealm
            };

            var responseToken = GssApiToken.EncodeIAKerbProxy(responseHeader, kdcResponse);

            // Record response token in transcript
            this.transcript.Write(responseToken.ToArray(), 0, responseToken.Length);

            return new IAKerbAcceptorResult(responseToken, isComplete: false);
        }

        private async Task<ReadOnlyMemory<byte>> SendRawMessage(
            string realm,
            ReadOnlyMemory<byte> message,
            CancellationToken cancellation
        )
        {
            // Use IKerberosTransport2 if available for raw byte transport
            if (this.kdcTransport is IKerberosTransport2 transport2)
            {
                return await transport2.SendMessage(realm, message, cancellation).ConfigureAwait(false);
            }

            throw new KerberosProtocolException(
                KerberosErrorCode.KRB_AP_ERR_IAKERB_KDC_NOT_FOUND,
                "Transport does not support raw message forwarding"
            );
        }

        private IAKerbAcceptorResult HandleApReq(
            ReadOnlyMemory<byte> inputToken,
            GssApiToken gssToken
        )
        {
            // This is the final AP-REQ - authenticate it
            var apReq = KrbApReq.DecodeApplication(gssToken.Token);

            var decryptedApReq = new DecryptedKrbApReq(apReq);
            decryptedApReq.Decrypt(this.serviceKeys);
            decryptedApReq.Validate(ValidationActions.All);

            // Validate GSS_EXTS_FINISHED
            ValidateFinishedChecksum(decryptedApReq);

            this.DecryptedApReq = decryptedApReq;
            this.State = IAKerbAcceptorState.Complete;

            // Generate AP-REP for mutual authentication if requested
            ReadOnlyMemory<byte>? apRepToken = null;

            if (apReq.ApOptions.HasFlag(ApOptions.MutualRequired))
            {
                var apRep = decryptedApReq.CreateResponseMessage();
                apRepToken = apRep.EncodeApplication();
            }

            return new IAKerbAcceptorResult(apRepToken, isComplete: true, decryptedApReq);
        }

        private void ValidateFinishedChecksum(DecryptedKrbApReq decryptedApReq)
        {
            var authenticator = decryptedApReq.Authenticator;

            if (authenticator.Subkey == null)
            {
                throw new KerberosValidationException(
                    "IAKerb AP-REQ must contain an authenticator subkey"
                );
            }

            if (authenticator.Checksum == null ||
                authenticator.Checksum.Type != KrbChecksum.ChecksumContainsDelegationType)
            {
                throw new KerberosValidationException(
                    "IAKerb AP-REQ must contain a delegation-type checksum with GSS_EXTS_FINISHED"
                );
            }

            // Decode delegation info to get extensions
            var delegationInfo = authenticator.Checksum.DecodeDelegation();

            if (delegationInfo.Extensions.Length == 0)
            {
                throw new KerberosValidationException(
                    "IAKerb AP-REQ must contain GSS_EXTS_FINISHED extension"
                );
            }

            // Decode the GSS extension - search for GSS_EXTS_FINISHED specifically
            var (extType, extData) = GssApiCfxExtensions.FindExtension(
                delegationInfo.Extensions,
                KrbFinished.GssExtsFinishedType
            );

            // Decode and verify the FINISHED checksum
            var finished = KrbFinished.Decode(extData);
            var transcriptBytes = this.transcript.ToArray();
            var subkey = authenticator.Subkey.AsKey();

            finished.Verify(transcriptBytes, subkey);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!this.disposed)
            {
                if (disposing)
                {
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
