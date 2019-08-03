using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using static Kerberos.NET.Win32.NativeMethods;

namespace Kerberos.NET.Win32
{
    internal partial class SspiSecurityContext : IDisposable
    {
        private const int SECPKG_CRED_BOTH = 0x00000003;
        private const int SECURITY_NETWORK_DREP = 0x00;

        private const int MaxTokenSize = 16 * 1024;

        private const ContextFlag DefaultRequiredFlags =
                                    ContextFlag.Connection |
                                    ContextFlag.ReplayDetect |
                                    ContextFlag.SequenceDetect |
                                    ContextFlag.Confidentiality |
                                    ContextFlag.AllocateMemory |
                                    ContextFlag.Delegate |
                                    ContextFlag.InitExtendedError;

        private const ContextFlag DefaultServerRequiredFlags =
                                    DefaultRequiredFlags |
                                    ContextFlag.AcceptStream |
                                    ContextFlag.AcceptExtendedError;

        private SECURITY_HANDLE credentialsHandle = new SECURITY_HANDLE();
        private SECURITY_HANDLE securityContext = new SECURITY_HANDLE();

        private readonly HashSet<object> disposable = new HashSet<object>();

        private readonly Credential credential;
        private readonly ContextFlag clientFlags;
        private readonly ContextFlag serverFlags;

        public SspiSecurityContext(
            Credential credential,
            string package,
            ContextFlag clientFlags = DefaultRequiredFlags,
            ContextFlag serverFlags = DefaultServerRequiredFlags
        )
        {
            this.credential = credential;
            this.clientFlags = clientFlags;
            this.serverFlags = serverFlags;

            Package = package;
        }

        public bool Impersonating { get; private set; }

        public string Package { get; }

        public string UserName { get { return QueryContextAttributeAsString(SecurityContextAttribute.SECPKG_ATTR_NAMES); } }

        public unsafe string QueryContextAttributeAsString(SecurityContextAttribute attr)
        {
            SecPkgContext_SecString pBuffer = default;
            SecStatus status;
            string strValue = null;

            RuntimeHelpers.PrepareConstrainedRegions();
            try { }
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
                        FreeContextBuffer(pBuffer.sValue);
                    }
                }

                if (status != SecStatus.SEC_E_UNSUPPORTED_FUNCTION && status > SecStatus.SEC_E_ERROR)
                {
                    throw new Win32Exception((int)status);
                }
            }

            return strValue;
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
                    clientToken = new SecBufferDesc(tokenSize);

                    if (!credentialsHandle.IsSet || result == SecStatus.SEC_I_CONTINUE_NEEDED)
                    {
                        AcquireCredentials();
                    }

                    if (serverResponse == null)
                    {
                        result = InitializeSecurityContext_0(
                            ref credentialsHandle,
                            IntPtr.Zero,
                            targetNameNormalized,
                            clientFlags,
                            0,
                            SECURITY_NETWORK_DREP,
                            IntPtr.Zero,
                            0,
                            ref securityContext,
                            ref clientToken,
                            out ContextFlag ContextFlags,
                            IntPtr.Zero
                        );
                    }
                    else
                    {
                        var pInputBuffer = new SecBufferDesc(serverResponse);
                        {
                            IntPtr pExpiry = IntPtr.Zero;

                            result = InitializeSecurityContext_1(
                                ref credentialsHandle,
                                ref securityContext,
                                targetNameNormalized,
                                clientFlags,
                                0,
                                SECURITY_NETWORK_DREP,
                                ref pInputBuffer,
                                0,
                                ref securityContext,
                                ref clientToken,
                                out ContextFlag ContextFlags,
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

            if (!credentialsHandle.IsSet)
            {
                AcquireCredentials();
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

                    if (!securityContext.IsSet)
                    {
                        result = AcceptSecurityContext_0(
                            ref credentialsHandle,
                            IntPtr.Zero,
                            ref pInput,
                            serverFlags,
                            SECURITY_NETWORK_DREP,
                            ref securityContext,
                            out pOutput,
                            out ContextFlag pfContextAttr,
                            out SECURITY_INTEGER ptsTimeStamp
                        );
                    }
                    else
                    {
                        result = AcceptSecurityContext_1(
                            ref credentialsHandle,
                            ref securityContext,
                            ref pInput,
                            serverFlags,
                            SECURITY_NETWORK_DREP,
                            ref securityContext,
                            out pOutput,
                            out ContextFlag pfContextAttr,
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

                TrackUnmanaged(securityContext);

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
            disposable.Add(thing);
        }

        private unsafe void AcquireCredentials()
        {
            CredentialHandle creds = credential.Structify();

            TrackUnmanaged(creds);

            SecStatus result;

            RuntimeHelpers.PrepareConstrainedRegions();
            try { }
            finally
            {
                result = AcquireCredentialsHandle(
                    null,
                    Package,
                    SECPKG_CRED_BOTH,
                    IntPtr.Zero,
                    (void*)creds.DangerousGetHandle(),
                    IntPtr.Zero,
                    IntPtr.Zero,
                    ref credentialsHandle,
                    IntPtr.Zero
               );
            }

            if (result != SecStatus.SEC_E_OK)
            {
                throw new Win32Exception((int)result);
            }

            TrackUnmanaged(credentialsHandle);
        }

        public unsafe void Dispose()
        {
            foreach (var thing in disposable)
            {
                if (thing is IDisposable managedDispose)
                {
                    managedDispose.Dispose();
                }
                else if (thing is SECURITY_HANDLE handle)
                {
                    DeleteSecurityContext(&handle);
                    FreeCredentialsHandle(&handle);
                }
                else if (thing is IntPtr pThing)
                {
                    Marshal.FreeHGlobal(pThing);
                }
            }
        }
    }
}
