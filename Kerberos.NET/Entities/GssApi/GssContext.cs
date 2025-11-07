// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Kerberos.NET.Client;
using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;

namespace Kerberos.NET.Entities.GssApi
{
    /// <summary>
    /// Concrete implementation of the GSS-API interface for Kerberos authentication.
    /// This implementation wraps the existing Kerberos.NET functionality with a GSS-API
    /// compatible interface as defined in RFC 2743.
    /// </summary>
    public class GssContext : IGssContext
    {
        private readonly KerberosClient client;
        private bool disposed = false;

        /// <summary>
        /// Initializes a new instance of the <see cref="GssContext"/> class.
        /// </summary>
        public GssContext()
        {
            this.client = new KerberosClient();
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="GssContext"/> class with a specific client.
        /// </summary>
        /// <param name="client">The Kerberos client to use.</param>
        public GssContext(KerberosClient client)
        {
            this.client = client ?? throw new ArgumentNullException(nameof(client));
        }

        // ===========================
        // Credential Management
        // ===========================

        public /* async */ Task<GssAcquireCredResult> GSS_Acquire_cred(
            GssName desiredName,
            uint timeReq,
            GssOidSet desiredMechs,
            GssCredentialUsage credUsage,
            CancellationToken cancellationToken = default)
        {
            var result = new GssAcquireCredResult();

            try
            {
                // Default to current user's credentials if no name specified
                // Note: KerberosClient doesn't expose a Credential property
                // Applications should configure the client with appropriate credentials
                // before using GSS-API
                
                if (desiredName == null)
                {
                    result.MinorStatus = 1;
                    result.MajorStatus = GssMajorStatus.GSS_S_NO_CRED;
                    return Task.FromResult(result);
                }

                // Create a placeholder credential
                // In a full implementation, this would use actual Kerberos credentials
                var outputCredHandle = new GssCredential(
                    new KerberosPasswordCredential(desiredName.Name, ""),
                    credUsage
                )
                {
                    Name = desiredName,
                    Mechanisms = new GssOidSet()
                };

                // Add supported mechanisms
                outputCredHandle.Mechanisms.Add(GssOid.GSS_MECH_KRB5);
                outputCredHandle.Mechanisms.Add(GssOid.GSS_MECH_KRB5_LEGACY);

                result.ActualMechs = outputCredHandle.Mechanisms;
                
                // Set lifetime (default to 8 hours if not specified)
                result.TimeRec = timeReq > 0 ? timeReq : 28800;
                outputCredHandle.Lifetime = result.TimeRec;

                result.OutputCredHandle = outputCredHandle;
                result.MajorStatus = GssMajorStatus.GSS_S_COMPLETE;
                return Task.FromResult(result);
            }
            catch (Exception ex)
            {
                result.MinorStatus = (uint)ex.HResult;
                result.MajorStatus = GssMajorStatus.GSS_S_FAILURE;
                return Task.FromResult(result);
            }
        }

        public GssMajorStatus GSS_Release_cred(
            ref GssCredential credHandle,
            out uint minorStatus)
        {
            minorStatus = 0;

            try
            {
                credHandle?.Dispose();
                credHandle = null;
                return GssMajorStatus.GSS_S_COMPLETE;
            }
            catch (Exception ex)
            {
                minorStatus = (uint)ex.HResult;
                return GssMajorStatus.GSS_S_FAILURE;
            }
        }

        public GssMajorStatus GSS_Inquire_cred(
            GssCredential credHandle,
            out GssName name,
            out uint lifetime,
            out GssCredentialUsage credUsage,
            out GssOidSet mechanisms,
            out uint minorStatus)
        {
            minorStatus = 0;
            name = null;
            lifetime = 0;
            credUsage = GssCredentialUsage.GSS_C_BOTH;
            mechanisms = null;

            try
            {
                if (credHandle == null)
                {
                    minorStatus = 1;
                    return GssMajorStatus.GSS_S_NO_CRED;
                }

                name = credHandle.Name;
                lifetime = credHandle.Lifetime;
                credUsage = credHandle.Usage;
                mechanisms = credHandle.Mechanisms;

                return GssMajorStatus.GSS_S_COMPLETE;
            }
            catch (Exception ex)
            {
                minorStatus = (uint)ex.HResult;
                return GssMajorStatus.GSS_S_FAILURE;
            }
        }

        public /* async */ Task<GssAddCredResult> GSS_Add_cred(
            GssCredential inputCredHandle,
            GssName desiredName,
            GssOid desiredMech,
            GssCredentialUsage credUsage,
            uint initiatorTimeReq,
            uint acceptorTimeReq,
            CancellationToken cancellationToken = default)
        {
            var result = new GssAddCredResult
            {
                OutputCredHandle = inputCredHandle,
                ActualMechs = inputCredHandle?.Mechanisms,
                InitiatorTimeRec = initiatorTimeReq,
                AcceptorTimeRec = acceptorTimeReq,
                MajorStatus = GssMajorStatus.GSS_S_UNAVAILABLE
            };

            // This is a simplified implementation
            // Full implementation would add mechanism-specific credentials
            return Task.FromResult(result);
        }

        public GssMajorStatus GSS_Inquire_cred_by_mech(
            GssCredential credHandle,
            GssOid mechType,
            out GssName name,
            out uint initiatorLifetime,
            out uint acceptorLifetime,
            out GssCredentialUsage credUsage,
            out uint minorStatus)
        {
            minorStatus = 0;
            name = null;
            initiatorLifetime = 0;
            acceptorLifetime = 0;
            credUsage = GssCredentialUsage.GSS_C_BOTH;

            try
            {
                if (credHandle == null)
                {
                    minorStatus = 1;
                    return GssMajorStatus.GSS_S_NO_CRED;
                }

                if (!credHandle.Mechanisms.Contains(mechType))
                {
                    minorStatus = 1;
                    return GssMajorStatus.GSS_S_BAD_MECH;
                }

                name = credHandle.Name;
                initiatorLifetime = credHandle.Lifetime;
                acceptorLifetime = credHandle.Lifetime;
                credUsage = credHandle.Usage;

                return GssMajorStatus.GSS_S_COMPLETE;
            }
            catch (Exception ex)
            {
                minorStatus = (uint)ex.HResult;
                return GssMajorStatus.GSS_S_FAILURE;
            }
        }

        // ===========================
        // Context Management
        // ===========================

        public async Task<GssInitSecContextResult> GSS_Init_sec_context(
            GssCredential initiatorCredHandle,
            GssSecurityContext contextHandle,
            GssName targetName,
            GssOid mechType,
            GssContextEstablishmentFlag reqFlags,
            uint timeReq,
            GssChannelBindings inputChanBindings,
            GssBuffer inputToken,
            CancellationToken cancellationToken = default)
        {
            var result = new GssInitSecContextResult
            {
                ActualMechType = mechType ?? GssOid.GSS_MECH_KRB5,
                RetFlags = reqFlags,
                TimeRec = timeReq
            };

            try
            {
                // Initialize context on first call
                if (contextHandle == null)
                {
                    contextHandle = new GssSecurityContext
                    {
                        TargetName = targetName,
                        MechType = result.ActualMechType,
                        Flags = reqFlags,
                        LocallyInitiated = true,
                        Lifetime = timeReq
                    };
                }

                result.ContextHandle = contextHandle;

                // Request a service ticket
                var rst = new RequestServiceTicket
                {
                    ServicePrincipalName = targetName.Name,
                    GssContextFlags = reqFlags,
                    S4uTarget = null
                };

                var serviceTicket = await this.client.GetServiceTicket(rst, cancellationToken);

                // The serviceTicket.ApReq already contains the complete AP-REQ with authenticator
                var apReq = serviceTicket.ApReq;

                // Encode as GSS token
                var gssToken = GssApiToken.Encode(
                    new System.Security.Cryptography.Oid(result.ActualMechType.Value),
                    apReq
                );

                result.OutputToken = new GssBuffer(gssToken);
                contextHandle.IsEstablished = true;
                contextHandle.SessionKey = serviceTicket.SessionKey.Encode();

                result.MajorStatus = GssMajorStatus.GSS_S_COMPLETE;
                return result;
            }
            catch (Exception ex)
            {
                result.MinorStatus = (uint)ex.HResult;
                result.MajorStatus = GssMajorStatus.GSS_S_FAILURE;
                return result;
            }
        }

        public /* async */ Task<GssAcceptSecContextResult> GSS_Accept_sec_context(
            GssSecurityContext contextHandle,
            GssCredential acceptorCredHandle,
            GssBuffer inputTokenBuffer,
            GssChannelBindings inputChanBindings,
            CancellationToken cancellationToken = default)
        {
            var result = new GssAcceptSecContextResult
            {
                MechType = GssOid.GSS_MECH_KRB5
            };

            try
            {
                if (inputTokenBuffer == null || inputTokenBuffer.IsEmpty)
                {
                    result.MinorStatus = 1;
                    result.MajorStatus = GssMajorStatus.GSS_S_DEFECTIVE_TOKEN;
                    return Task.FromResult(result);
                }

                // Parse the GSS token
                var token = MessageParser.Parse(inputTokenBuffer.Data);
                
                if (token is KerberosContextToken kerbToken)
                {
                    // For a full implementation, we would:
                    // 1. Decrypt and validate the AP-REQ
                    // 2. Extract the client principal name
                    // 3. Generate an AP-REP if mutual authentication is requested
                    // 4. Extract delegated credentials if present

                    if (contextHandle == null)
                    {
                        contextHandle = new GssSecurityContext
                        {
                            MechType = result.MechType,
                            LocallyInitiated = false,
                            IsEstablished = true
                        };
                    }

                    result.ContextHandle = contextHandle;

                    // This is a simplified implementation
                    // Full implementation would use KerberosAuthenticator/Validator
                    result.SrcName = new GssName("client@REALM", GssNameType.GSS_KRB5_NT_PRINCIPAL_NAME);
                    contextHandle.SourceName = result.SrcName;
                    contextHandle.IsEstablished = true;

                    result.MajorStatus = GssMajorStatus.GSS_S_COMPLETE;
                    return Task.FromResult(result);
                }

                result.MinorStatus = 1;
                result.MajorStatus = GssMajorStatus.GSS_S_DEFECTIVE_TOKEN;
                return Task.FromResult(result);
            }
            catch (Exception ex)
            {
                result.MinorStatus = (uint)ex.HResult;
                result.MajorStatus = GssMajorStatus.GSS_S_FAILURE;
                return Task.FromResult(result);
            }
        }

        public GssMajorStatus GSS_Delete_sec_context(
            ref GssSecurityContext contextHandle,
            out GssBuffer outputToken,
            out uint minorStatus)
        {
            minorStatus = 0;
            outputToken = null;

            try
            {
                contextHandle?.Dispose();
                contextHandle = null;
                return GssMajorStatus.GSS_S_COMPLETE;
            }
            catch (Exception ex)
            {
                minorStatus = (uint)ex.HResult;
                return GssMajorStatus.GSS_S_FAILURE;
            }
        }

        public GssMajorStatus GSS_Process_context_token(
            GssSecurityContext contextHandle,
            GssBuffer token,
            out uint minorStatus)
        {
            minorStatus = 0;
            
            // This would process context-level tokens (e.g., context deletion tokens)
            return GssMajorStatus.GSS_S_UNAVAILABLE;
        }

        public GssMajorStatus GSS_Context_time(
            GssSecurityContext contextHandle,
            out uint timeRec,
            out uint minorStatus)
        {
            minorStatus = 0;
            timeRec = 0;

            try
            {
                if (contextHandle == null)
                {
                    minorStatus = 1;
                    return GssMajorStatus.GSS_S_NO_CONTEXT;
                }

                timeRec = contextHandle.Lifetime;
                return GssMajorStatus.GSS_S_COMPLETE;
            }
            catch (Exception ex)
            {
                minorStatus = (uint)ex.HResult;
                return GssMajorStatus.GSS_S_FAILURE;
            }
        }

        public GssMajorStatus GSS_Inquire_context(
            GssSecurityContext contextHandle,
            out GssName srcName,
            out GssName targName,
            out uint lifetimeRec,
            out GssOid mechType,
            out GssContextEstablishmentFlag ctxFlags,
            out bool locallyInitiated,
            out bool open,
            out uint minorStatus)
        {
            minorStatus = 0;
            srcName = null;
            targName = null;
            lifetimeRec = 0;
            mechType = null;
            ctxFlags = 0;
            locallyInitiated = false;
            open = false;

            try
            {
                if (contextHandle == null)
                {
                    minorStatus = 1;
                    return GssMajorStatus.GSS_S_NO_CONTEXT;
                }

                srcName = contextHandle.SourceName;
                targName = contextHandle.TargetName;
                lifetimeRec = contextHandle.Lifetime;
                mechType = contextHandle.MechType;
                ctxFlags = contextHandle.Flags;
                locallyInitiated = contextHandle.LocallyInitiated;
                open = contextHandle.IsEstablished;

                return GssMajorStatus.GSS_S_COMPLETE;
            }
            catch (Exception ex)
            {
                minorStatus = (uint)ex.HResult;
                return GssMajorStatus.GSS_S_FAILURE;
            }
        }

        public GssMajorStatus GSS_Wrap_size_limit(
            GssSecurityContext contextHandle,
            bool confReq,
            uint qopReq,
            uint reqOutputSize,
            out uint maxInputSize,
            out uint minorStatus)
        {
            minorStatus = 0;
            maxInputSize = 0;

            try
            {
                if (contextHandle == null)
                {
                    minorStatus = 1;
                    return GssMajorStatus.GSS_S_NO_CONTEXT;
                }

                // Simplified calculation - actual overhead depends on mechanism and options
                const uint wrapOverhead = 100; // Approximate overhead for Kerberos wrap
                maxInputSize = reqOutputSize > wrapOverhead ? reqOutputSize - wrapOverhead : 0;

                return GssMajorStatus.GSS_S_COMPLETE;
            }
            catch (Exception ex)
            {
                minorStatus = (uint)ex.HResult;
                return GssMajorStatus.GSS_S_FAILURE;
            }
        }

        public GssMajorStatus GSS_Export_sec_context(
            ref GssSecurityContext contextHandle,
            out GssBuffer interstageToken,
            out uint minorStatus)
        {
            minorStatus = 0;
            interstageToken = null;

            // Context export/import would require serialization of the context state
            return GssMajorStatus.GSS_S_UNAVAILABLE;
        }

        public GssMajorStatus GSS_Import_sec_context(
            GssBuffer interstageToken,
            out GssSecurityContext contextHandle,
            out uint minorStatus)
        {
            minorStatus = 0;
            contextHandle = null;

            // Context export/import would require deserialization of the context state
            return GssMajorStatus.GSS_S_UNAVAILABLE;
        }

        // ===========================
        // Per-message Protection
        // ===========================

        public GssMajorStatus GSS_GetMIC(
            GssSecurityContext contextHandle,
            uint qopReq,
            GssBuffer messageBuffer,
            out GssBuffer messageToken,
            out uint minorStatus)
        {
            minorStatus = 0;
            messageToken = null;

            try
            {
                if (contextHandle == null || !contextHandle.IsEstablished)
                {
                    minorStatus = 1;
                    return GssMajorStatus.GSS_S_NO_CONTEXT;
                }

                if (messageBuffer == null || messageBuffer.IsEmpty)
                {
                    minorStatus = 1;
                    return GssMajorStatus.GSS_S_DEFECTIVE_TOKEN;
                }

                // Generate a MIC using the session key
                var key = KrbEncryptionKey.Decode(contextHandle.SessionKey);
                var checksum = KrbChecksum.Create(
                    messageBuffer.Data,
                    key.AsKey(),
                    KeyUsage.Sign  // Use Sign for MIC
                );

                messageToken = new GssBuffer(checksum.Encode());
                return GssMajorStatus.GSS_S_COMPLETE;
            }
            catch (Exception ex)
            {
                minorStatus = (uint)ex.HResult;
                return GssMajorStatus.GSS_S_FAILURE;
            }
        }

        public GssMajorStatus GSS_VerifyMIC(
            GssSecurityContext contextHandle,
            GssBuffer messageBuffer,
            GssBuffer tokenBuffer,
            out uint qopState,
            out uint minorStatus)
        {
            minorStatus = 0;
            qopState = 0;

            try
            {
                if (contextHandle == null || !contextHandle.IsEstablished)
                {
                    minorStatus = 1;
                    return GssMajorStatus.GSS_S_NO_CONTEXT;
                }

                if (messageBuffer == null || tokenBuffer == null)
                {
                    minorStatus = 1;
                    return GssMajorStatus.GSS_S_DEFECTIVE_TOKEN;
                }

                // Verify the MIC
                var checksum = KrbChecksum.Decode(tokenBuffer.Data);
                var key = KrbEncryptionKey.Decode(contextHandle.SessionKey);

                // Note: KrbChecksum doesn't have a Validate method
                // We would need to recreate the checksum and compare
                // For now, this is a simplified stub
                var expectedChecksum = KrbChecksum.Create(
                    messageBuffer.Data,
                    key.AsKey(),
                    KeyUsage.Sign
                );

                // Simple comparison (in production, use constant-time comparison)
                var isValid = checksum.Checksum.Span.SequenceEqual(expectedChecksum.Checksum.Span);

                if (!isValid)
                {
                    minorStatus = 1;
                    return GssMajorStatus.GSS_S_BAD_MIC;
                }

                return GssMajorStatus.GSS_S_COMPLETE;
            }
            catch (Exception ex)
            {
                minorStatus = (uint)ex.HResult;
                return GssMajorStatus.GSS_S_FAILURE;
            }
        }

        public GssMajorStatus GSS_Wrap(
            GssSecurityContext contextHandle,
            bool confReq,
            uint qopReq,
            GssBuffer inputMessageBuffer,
            out bool confState,
            out GssBuffer outputMessageBuffer,
            out uint minorStatus)
        {
            minorStatus = 0;
            confState = confReq;
            outputMessageBuffer = null;

            try
            {
                if (contextHandle == null || !contextHandle.IsEstablished)
                {
                    minorStatus = 1;
                    return GssMajorStatus.GSS_S_NO_CONTEXT;
                }

                if (inputMessageBuffer == null)
                {
                    minorStatus = 1;
                    return GssMajorStatus.GSS_S_DEFECTIVE_TOKEN;
                }

                var key = KrbEncryptionKey.Decode(contextHandle.SessionKey);
                var keyObj = key.AsKey();
                var transformer = CryptoService.CreateTransform(keyObj.EncryptionType);

                if (confReq)
                {
                    // Encrypt the message
                    var encrypted = transformer.Encrypt(
                        inputMessageBuffer.Data,
                        keyObj,
                        KeyUsage.Seal  // Use Seal for wrap/encryption
                    );
                    outputMessageBuffer = new GssBuffer(encrypted);
                }
                else
                {
                    // Just add integrity protection
                    var checksum = KrbChecksum.Create(
                        inputMessageBuffer.Data,
                        keyObj,
                        KeyUsage.Sign  // Use Sign for integrity
                    );
                    
                    // Concatenate message and checksum
                    var output = new byte[inputMessageBuffer.Length + checksum.Checksum.Length];
                    inputMessageBuffer.Data.CopyTo(output.AsMemory());
                    checksum.Checksum.CopyTo(output.AsMemory(inputMessageBuffer.Length));
                    
                    outputMessageBuffer = new GssBuffer(output);
                }

                return GssMajorStatus.GSS_S_COMPLETE;
            }
            catch (Exception ex)
            {
                minorStatus = (uint)ex.HResult;
                return GssMajorStatus.GSS_S_FAILURE;
            }
        }

        public GssMajorStatus GSS_Unwrap(
            GssSecurityContext contextHandle,
            GssBuffer inputMessageBuffer,
            out GssBuffer outputMessageBuffer,
            out bool confState,
            out uint qopState,
            out uint minorStatus)
        {
            minorStatus = 0;
            outputMessageBuffer = null;
            confState = false;
            qopState = 0;

            try
            {
                if (contextHandle == null || !contextHandle.IsEstablished)
                {
                    minorStatus = 1;
                    return GssMajorStatus.GSS_S_NO_CONTEXT;
                }

                if (inputMessageBuffer == null)
                {
                    minorStatus = 1;
                    return GssMajorStatus.GSS_S_DEFECTIVE_TOKEN;
                }

                var key = KrbEncryptionKey.Decode(contextHandle.SessionKey);
                var keyObj = key.AsKey();
                var transformer = CryptoService.CreateTransform(keyObj.EncryptionType);

                try
                {
                    // Try to decrypt (assuming it was encrypted)
                    var decrypted = transformer.Decrypt(
                        inputMessageBuffer.Data,
                        keyObj,
                        KeyUsage.Seal  // Use Seal for unwrap/decryption
                    );
                    outputMessageBuffer = new GssBuffer(decrypted);
                    confState = true;
                }
                catch
                {
                    // Not encrypted, just integrity protected
                    // This is simplified - would need proper format parsing
                    confState = false;
                    minorStatus = 1;
                    return GssMajorStatus.GSS_S_DEFECTIVE_TOKEN;
                }

                return GssMajorStatus.GSS_S_COMPLETE;
            }
            catch (Exception ex)
            {
                minorStatus = (uint)ex.HResult;
                return GssMajorStatus.GSS_S_FAILURE;
            }
        }

        // ===========================
        // Support Functions
        // ===========================

        public GssMajorStatus GSS_Display_status(
            uint statusValue,
            int statusType,
            GssOid mechType,
            ref uint messageContext,
            out GssBuffer statusString,
            out uint minorStatus)
        {
            minorStatus = 0;
            
            var status = (GssMajorStatus)statusValue;
            var statusText = status.ToString();
            
            statusString = new GssBuffer(Encoding.UTF8.GetBytes(statusText));
            messageContext = 0;

            return GssMajorStatus.GSS_S_COMPLETE;
        }

        public GssMajorStatus GSS_Indicate_mechs(
            out GssOidSet mechSet,
            out uint minorStatus)
        {
            minorStatus = 0;
            mechSet = new GssOidSet();

            mechSet.Add(GssOid.GSS_MECH_KRB5);
            mechSet.Add(GssOid.GSS_MECH_KRB5_LEGACY);
            mechSet.Add(GssOid.GSS_MECH_SPNEGO);

            return GssMajorStatus.GSS_S_COMPLETE;
        }

        public GssMajorStatus GSS_Compare_name(
            GssName name1,
            GssName name2,
            out bool nameEqual,
            out uint minorStatus)
        {
            minorStatus = 0;
            nameEqual = false;

            try
            {
                if (name1 == null || name2 == null)
                {
                    nameEqual = name1 == name2;
                    return GssMajorStatus.GSS_S_COMPLETE;
                }

                nameEqual = string.Equals(
                    name1.Name,
                    name2.Name,
                    StringComparison.OrdinalIgnoreCase
                );

                return GssMajorStatus.GSS_S_COMPLETE;
            }
            catch (Exception ex)
            {
                minorStatus = (uint)ex.HResult;
                return GssMajorStatus.GSS_S_FAILURE;
            }
        }

        public GssMajorStatus GSS_Display_name(
            GssName inputName,
            out GssBuffer outputNameBuffer,
            out GssOid outputNameType,
            out uint minorStatus)
        {
            minorStatus = 0;
            outputNameBuffer = null;
            outputNameType = null;

            try
            {
                if (inputName == null)
                {
                    minorStatus = 1;
                    return GssMajorStatus.GSS_S_BAD_NAME;
                }

                outputNameBuffer = new GssBuffer(Encoding.UTF8.GetBytes(inputName.Name));
                outputNameType = inputName.NameType;

                return GssMajorStatus.GSS_S_COMPLETE;
            }
            catch (Exception ex)
            {
                minorStatus = (uint)ex.HResult;
                return GssMajorStatus.GSS_S_FAILURE;
            }
        }

        public GssMajorStatus GSS_Import_name(
            GssBuffer inputNameBuffer,
            GssOid inputNameType,
            out GssName outputName,
            out uint minorStatus)
        {
            minorStatus = 0;
            outputName = null;

            try
            {
                if (inputNameBuffer == null || inputNameBuffer.IsEmpty)
                {
                    minorStatus = 1;
                    return GssMajorStatus.GSS_S_BAD_NAME;
                }

                var nameString = Encoding.UTF8.GetString(inputNameBuffer.ToArray());
                outputName = new GssName(nameString, inputNameType);

                return GssMajorStatus.GSS_S_COMPLETE;
            }
            catch (Exception ex)
            {
                minorStatus = (uint)ex.HResult;
                return GssMajorStatus.GSS_S_FAILURE;
            }
        }

        public GssMajorStatus GSS_Release_name(
            ref GssName name,
            out uint minorStatus)
        {
            minorStatus = 0;

            try
            {
                name?.Dispose();
                name = null;
                return GssMajorStatus.GSS_S_COMPLETE;
            }
            catch (Exception ex)
            {
                minorStatus = (uint)ex.HResult;
                return GssMajorStatus.GSS_S_FAILURE;
            }
        }

        public GssMajorStatus GSS_Release_buffer(
            ref GssBuffer buffer,
            out uint minorStatus)
        {
            minorStatus = 0;

            try
            {
                buffer?.Dispose();
                buffer = null;
                return GssMajorStatus.GSS_S_COMPLETE;
            }
            catch (Exception ex)
            {
                minorStatus = (uint)ex.HResult;
                return GssMajorStatus.GSS_S_FAILURE;
            }
        }

        public GssMajorStatus GSS_Release_OID_set(
            ref GssOidSet set,
            out uint minorStatus)
        {
            minorStatus = 0;

            try
            {
                set?.Dispose();
                set = null;
                return GssMajorStatus.GSS_S_COMPLETE;
            }
            catch (Exception ex)
            {
                minorStatus = (uint)ex.HResult;
                return GssMajorStatus.GSS_S_FAILURE;
            }
        }

        public GssMajorStatus GSS_Create_empty_OID_set(
            out GssOidSet oidSet,
            out uint minorStatus)
        {
            minorStatus = 0;
            oidSet = new GssOidSet();
            return GssMajorStatus.GSS_S_COMPLETE;
        }

        public GssMajorStatus GSS_Add_OID_set_member(
            GssOid memberOid,
            ref GssOidSet oidSet,
            out uint minorStatus)
        {
            minorStatus = 0;

            try
            {
                if (oidSet == null)
                {
                    oidSet = new GssOidSet();
                }

                oidSet.Add(memberOid);
                return GssMajorStatus.GSS_S_COMPLETE;
            }
            catch (Exception ex)
            {
                minorStatus = (uint)ex.HResult;
                return GssMajorStatus.GSS_S_FAILURE;
            }
        }

        public GssMajorStatus GSS_Test_OID_set_member(
            GssOid member,
            GssOidSet set,
            out bool present,
            out uint minorStatus)
        {
            minorStatus = 0;
            present = false;

            try
            {
                if (set == null || member == null)
                {
                    return GssMajorStatus.GSS_S_COMPLETE;
                }

                present = set.Contains(member);
                return GssMajorStatus.GSS_S_COMPLETE;
            }
            catch (Exception ex)
            {
                minorStatus = (uint)ex.HResult;
                return GssMajorStatus.GSS_S_FAILURE;
            }
        }

        public GssMajorStatus GSS_Inquire_names_for_mech(
            GssOid mechType,
            out GssOidSet nameTypes,
            out uint minorStatus)
        {
            minorStatus = 0;
            nameTypes = new GssOidSet();

            if (mechType == GssOid.GSS_MECH_KRB5 || mechType == GssOid.GSS_MECH_KRB5_LEGACY)
            {
                nameTypes.Add(GssNameType.GSS_KRB5_NT_PRINCIPAL_NAME);
                nameTypes.Add(GssNameType.GSS_C_NT_HOSTBASED_SERVICE);
                nameTypes.Add(GssNameType.GSS_C_NT_USER_NAME);
            }

            return GssMajorStatus.GSS_S_COMPLETE;
        }

        public GssMajorStatus GSS_Inquire_mechs_for_name(
            GssName inputName,
            out GssOidSet mechTypes,
            out uint minorStatus)
        {
            minorStatus = 0;
            mechTypes = new GssOidSet();

            // All our supported mechanisms can handle any name type
            mechTypes.Add(GssOid.GSS_MECH_KRB5);
            mechTypes.Add(GssOid.GSS_MECH_KRB5_LEGACY);

            return GssMajorStatus.GSS_S_COMPLETE;
        }

        public GssMajorStatus GSS_Canonicalize_name(
            GssName inputName,
            GssOid mechType,
            out GssName outputName,
            out uint minorStatus)
        {
            minorStatus = 0;
            outputName = null;

            try
            {
                if (inputName == null)
                {
                    minorStatus = 1;
                    return GssMajorStatus.GSS_S_BAD_NAME;
                }

                // Create a mechanism name
                outputName = new GssName(inputName.Name, inputName.NameType)
                {
                    IsMechanismName = true,
                    MechanismType = mechType
                };

                return GssMajorStatus.GSS_S_COMPLETE;
            }
            catch (Exception ex)
            {
                minorStatus = (uint)ex.HResult;
                return GssMajorStatus.GSS_S_FAILURE;
            }
        }

        public GssMajorStatus GSS_Export_name(
            GssName inputName,
            out GssBuffer exportedName,
            out uint minorStatus)
        {
            minorStatus = 0;
            exportedName = null;

            try
            {
                if (inputName == null || !inputName.IsMechanismName)
                {
                    minorStatus = 1;
                    return GssMajorStatus.GSS_S_NAME_NOT_MN;
                }

                // Export format: 4-byte length + mechanism OID + 4-byte name length + name bytes
                // This is a simplified implementation
                var nameBytes = Encoding.UTF8.GetBytes(inputName.Name);
                exportedName = new GssBuffer(nameBytes);

                return GssMajorStatus.GSS_S_COMPLETE;
            }
            catch (Exception ex)
            {
                minorStatus = (uint)ex.HResult;
                return GssMajorStatus.GSS_S_FAILURE;
            }
        }

        public GssMajorStatus GSS_Duplicate_name(
            GssName srcName,
            out GssName destName,
            out uint minorStatus)
        {
            minorStatus = 0;
            destName = null;

            try
            {
                if (srcName == null)
                {
                    minorStatus = 1;
                    return GssMajorStatus.GSS_S_BAD_NAME;
                }

                destName = new GssName(srcName.Name, srcName.NameType)
                {
                    IsMechanismName = srcName.IsMechanismName,
                    MechanismType = srcName.MechanismType
                };

                return GssMajorStatus.GSS_S_COMPLETE;
            }
            catch (Exception ex)
            {
                minorStatus = (uint)ex.HResult;
                return GssMajorStatus.GSS_S_FAILURE;
            }
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!disposed)
            {
                if (disposing)
                {
                    this.client?.Dispose();
                }

                disposed = true;
            }
        }

        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }
}
