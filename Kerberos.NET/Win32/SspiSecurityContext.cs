// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using static Kerberos.NET.Win32.NativeMethods;

namespace Kerberos.NET.Win32
{
    [ExcludeFromCodeCoverage]
    internal partial class SspiSecurityContext : IDisposable
    {
        private const int SECPKG_CRED_BOTH = 0x00000003;
        private const int SECURITY_NETWORK_DREP = 0x00;

        private const int MaxTokenSize = 16 * 1024;

        private const InitContextFlag DefaultRequiredFlags =
                                    InitContextFlag.Connection |
                                    InitContextFlag.ReplayDetect |
                                    InitContextFlag.SequenceDetect |
                                    InitContextFlag.Confidentiality |
                                    InitContextFlag.AllocateMemory |
                                    InitContextFlag.Delegate |
                                    InitContextFlag.InitExtendedError;

        private const AcceptContextFlag DefaultServerRequiredFlags =
                                    AcceptContextFlag.Connection |
                                    AcceptContextFlag.ReplayDetect |
                                    AcceptContextFlag.SequenceDetect |
                                    AcceptContextFlag.Confidentiality |
                                    AcceptContextFlag.AllocateMemory |
                                    AcceptContextFlag.Delegate |
                                    AcceptContextFlag.AcceptStream |
                                    AcceptContextFlag.AcceptExtendedError;

        private readonly HashSet<object> disposable = new();

        private readonly Credential credential;
        private readonly InitContextFlag clientFlags;
        private readonly AcceptContextFlag serverFlags;

        private SECURITY_HANDLE credentialsHandle = default;
        private SECURITY_HANDLE securityContext = default;

        public SspiSecurityContext(
            Credential credential,
            string package,
            InitContextFlag clientFlags = DefaultRequiredFlags,
            AcceptContextFlag serverFlags = DefaultServerRequiredFlags
        )
        {
            this.credential = credential;
            this.clientFlags = clientFlags;
            this.serverFlags = serverFlags;

            this.Package = package;
        }

        public bool Impersonating { get; private set; }

        public string Package { get; }

        public string UserName => this.QueryContextAttributeAsString(SecurityContextAttribute.SECPKG_ATTR_NAMES);

        public unsafe string QueryContextAttributeAsString(SecurityContextAttribute attr)
        {
            SecPkgContext_SecString pBuffer = default;
            SecStatus status;
            string strValue = null;

            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
            }
            finally
            {
                status = QueryContextAttributesString(ref this.securityContext, attr, ref pBuffer);

                if (status == SecStatus.SEC_E_OK)
                {
                    try
                    {
                        strValue = Marshal.PtrToStringUni((IntPtr)pBuffer.sValue);
                    }
                    finally
                    {
                        ThrowIfError(FreeContextBuffer(pBuffer.sValue));
                    }
                }
            }

            if (status != SecStatus.SEC_E_UNSUPPORTED_FUNCTION && status > SecStatus.SEC_E_ERROR)
            {
                throw new Win32Exception((int)status);
            }

            return strValue;
        }

        public unsafe byte[] QueryContextAttributeSession()
        {
            SecPkgContext_SessionKey pBuffer = default;
            SecStatus status;
            byte[] bytes = null;
            
            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
            }
            finally
            {
                try
                {
                    status = QueryContextAttributesSession(ref this.securityContext, SecurityContextAttribute.SECPKG_ATTR_SESSION_KEY, ref pBuffer);

                    if (status == SecStatus.SEC_E_OK)
                    {
                        bytes = new Span<byte>(pBuffer.SessionKey, (int)pBuffer.SessionKeyLength).ToArray();
                    }
                }
                finally
                {
                    ThrowIfError(FreeContextBuffer(pBuffer.SessionKey));
                }
            }

            if (status != SecStatus.SEC_E_UNSUPPORTED_FUNCTION && status > SecStatus.SEC_E_ERROR)
            {
                throw new Win32Exception((int)status);
            }

            return bytes;
        }

        private static void ThrowIfError(uint result)
        {
            if (result != 0 && result != 0x80090301)
            {
                throw new Win32Exception((int)result);
            }
        }

        public ContextStatus InitializeSecurityContext(string targetName, byte[] serverResponse, out byte[] clientRequest)
        {
            var targetNameNormalized = targetName.ToLowerInvariant();

            clientRequest = null;

            // 1. acquire
            // 2. initialize
            // 3. ??

            SecStatus result = 0;

            int tokenSize = 0;

            SecBufferDesc clientToken = default;

            try
            {
                do
                {
                    InitContextFlag contextFlags;

                    clientToken = new SecBufferDesc(tokenSize);

                    if (!this.credentialsHandle.IsSet || result == SecStatus.SEC_I_CONTINUE_NEEDED)
                    {
                        this.AcquireCredentials();
                    }

                    if (serverResponse == null)
                    {
                        result = InitializeSecurityContext_0(
                            ref this.credentialsHandle,
                            IntPtr.Zero,
                            targetNameNormalized,
                            this.clientFlags,
                            0,
                            SECURITY_NETWORK_DREP,
                            IntPtr.Zero,
                            0,
                            ref this.securityContext,
                            ref clientToken,
                            out contextFlags,
                            IntPtr.Zero
                        );
                    }
                    else
                    {
                        var pInputBuffer = new SecBufferDesc(serverResponse);
                        {
                            IntPtr pExpiry = IntPtr.Zero;

                            result = InitializeSecurityContext_1(
                                ref this.credentialsHandle,
                                ref this.securityContext,
                                targetNameNormalized,
                                this.clientFlags,
                                0,
                                SECURITY_NETWORK_DREP,
                                ref pInputBuffer,
                                0,
                                ref this.securityContext,
                                ref clientToken,
                                out contextFlags,
                                ref pExpiry
                            );
                        }
                    }

                    if (result == SecStatus.SEC_E_INSUFFICENT_MEMORY)
                    {
                        if (tokenSize > MaxTokenSize)
                        {
                            break;
                        }

                        tokenSize += 1000;
                    }
                }
                while (result == SecStatus.SEC_I_INCOMPLETE_CREDENTIALS || result == SecStatus.SEC_E_INSUFFICENT_MEMORY);

                this.TrackUnmanaged(this.securityContext);

                if (result > SecStatus.SEC_E_ERROR)
                {
                    throw new Win32Exception((int)result);
                }

                clientRequest = clientToken.ReadBytes();

                if (result == SecStatus.SEC_I_CONTINUE_NEEDED)
                {
                    return ContextStatus.RequiresContinuation;
                }

                return ContextStatus.Accepted;
            }
            finally
            {
                clientToken.Dispose();
            }
        }

        public ContextStatus AcceptSecurityContext(byte[] clientRequest, out byte[] serverResponse)
        {
            serverResponse = null;

            if (!this.credentialsHandle.IsSet)
            {
                this.AcquireCredentials();
            }

            var pInput = new SecBufferDesc(clientRequest);

            var tokenSize = 0;
            SecBufferDesc pOutput = default;

            try
            {
                SecStatus result;

                do
                {
                    pOutput = new SecBufferDesc(tokenSize);

                    if (!this.securityContext.IsSet)
                    {
                        result = AcceptSecurityContext_0(
                            ref this.credentialsHandle,
                            IntPtr.Zero,
                            ref pInput,
                            this.serverFlags,
                            SECURITY_NETWORK_DREP,
                            ref this.securityContext,
                            out pOutput,
                            out AcceptContextFlag pfContextAttr,
                            out SECURITY_INTEGER ptsTimeStamp
                        );
                    }
                    else
                    {
                        result = AcceptSecurityContext_1(
                            ref this.credentialsHandle,
                            ref this.securityContext,
                            ref pInput,
                            this.serverFlags,
                            SECURITY_NETWORK_DREP,
                            ref this.securityContext,
                            out pOutput,
                            out AcceptContextFlag pfContextAttr,
                            out SECURITY_INTEGER ptsTimeStamp
                        );
                    }

                    if (result == SecStatus.SEC_E_INSUFFICENT_MEMORY)
                    {
                        if (tokenSize > MaxTokenSize)
                        {
                            break;
                        }

                        tokenSize += 1000;
                    }
                }
                while (result == SecStatus.SEC_I_INCOMPLETE_CREDENTIALS || result == SecStatus.SEC_E_INSUFFICENT_MEMORY);

                this.TrackUnmanaged(this.securityContext);

                if (result > SecStatus.SEC_E_ERROR)
                {
                    throw new Win32Exception((int)result);
                }

                serverResponse = pOutput.ReadBytes();

                if (result == SecStatus.SEC_I_CONTINUE_NEEDED)
                {
                    return ContextStatus.RequiresContinuation;
                }

                return ContextStatus.Accepted;
            }
            finally
            {
                pInput.Dispose();
                pOutput.Dispose();
            }
        }

        private void TrackUnmanaged(object thing)
        {
            this.disposable.Add(thing);
        }

        private unsafe void AcquireCredentials()
        {
            CredentialHandle creds = this.credential.Structify();

            this.TrackUnmanaged(creds);

            SecStatus result;

            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
            }
            finally
            {
                result = AcquireCredentialsHandle(
                    null,
                    this.Package,
                    SECPKG_CRED_BOTH,
                    IntPtr.Zero,
                    (void*)creds.DangerousGetHandle(),
                    IntPtr.Zero,
                    IntPtr.Zero,
                    ref this.credentialsHandle,
                    IntPtr.Zero
               );
            }

            if (result != SecStatus.SEC_E_OK)
            {
                throw new Win32Exception((int)result);
            }

            this.TrackUnmanaged(this.credentialsHandle);
        }

        public unsafe void Dispose()
        {
            foreach (var thing in this.disposable)
            {
                if (thing is IDisposable managedDispose)
                {
                    managedDispose.Dispose();
                }
                else if (thing is SECURITY_HANDLE handle)
                {
                    DeleteSecurityContext(&handle);

                    ThrowIfError(FreeCredentialsHandle(&handle));
                }
                else if (thing is IntPtr pThing)
                {
                    Marshal.FreeHGlobal(pThing);
                }
            }
        }
    }
}
