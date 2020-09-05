// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Kerberos.NET.Entities;
using static Kerberos.NET.Win32.NativeMethods;

namespace Kerberos.NET.Win32
{
    /// <summary>
    /// Provides a layer to interact with the LSA functions used to create logon sessions and manipulate the ticket caches.
    /// </summary>
    public class LsaInterop : IDisposable
    {
        private const string KerberosPackageName = "Kerberos";
        private const string NegotiatePackageName = "Negotiate";
        private const string ProcessName = "KerberosNet";
        private const string DefaultUserName = "user";

        private readonly LsaSafeHandle lsaHandle;
        private readonly int selectedAuthPackage;
        private readonly int negotiateAuthPackage;

        private LsaTokenSafeHandle impersonationContext;
        private LUID luid;

        private bool disposedValue;

        /*
         * Windows creates a new ticket cache for primary NT tokens. This allows callers to create a dedicated cache for whatever they're doing
         * that way the cache operations like purge or import don't polute the current users cache.
         *
         * To make this work we need to create a new NT token, which is only done during logon. We don't actually want Windows to validate the credentials
         * so we tell it to treat the logon as `NewCredentials` which means Windows will just use those credentials as SSO credentials only.
         *
         * From there a new cache is created and any operations against the "current cache" such as SSPI ISC calls will hit this new cache.
         * We then let callers import tickets into that cache using the krb-cred structure.
         *
         * When done the call to dispose will
         * 1. Revert the impersonation context
         * 2. Close the NT token handle
         * 3. Close the Lsa Handle
         *
         * This destroys the cache and closes the logon session.
         *
         * For any operation that require native allocation and PtrToStructure copies we try and use the CryptoPool mechanism, which checks out a shared
         * pool of memory to create a working for the current operation. On dispose it zeros the memory and returns it to the pool.
         */

        private LsaInterop(LsaSafeHandle lsaHandle, string packageName = KerberosPackageName)
        {
            this.lsaHandle = lsaHandle;

            var kerberosPackageName = new LSA_STRING
            {
                Buffer = packageName,
                Length = (ushort)packageName.Length,
                MaximumLength = (ushort)packageName.Length
            };

            var result = LsaLookupAuthenticationPackage(this.lsaHandle, ref kerberosPackageName, out this.selectedAuthPackage);
            LsaThrowIfError(result);

            var negotiatePackageName = new LSA_STRING
            {
                Buffer = NegotiatePackageName,
                Length = (ushort)NegotiatePackageName.Length,
                MaximumLength = (ushort)NegotiatePackageName.Length
            };

            result = LsaLookupAuthenticationPackage(this.lsaHandle, ref negotiatePackageName, out this.negotiateAuthPackage);
            LsaThrowIfError(result);
        }

        /// <summary>
        /// Create a new instance of the interop and allow this instance to behave as SYSTEM.
        /// Note that this call requires the TrustedComputingBase privilege to execute.
        /// </summary>
        /// <param name="name">The optional logical name of the process as understood by LSA. Otherwise uses the default "KerberosNet".</param>
        /// <param name="package">The name of the LSA authentication package that will be interacted with.</param>
        /// <returns>Returns an instance of the <see cref="LsaInterop"/> class.</returns>
        public static LsaInterop RegisterLogonProcess(string name = null, string package = KerberosPackageName)
        {
            string processNameStr;

            if (string.IsNullOrWhiteSpace(name))
            {
                processNameStr = ProcessName;
            }
            else
            {
                processNameStr = name;
            }

            if (string.IsNullOrWhiteSpace(package))
            {
                package = KerberosPackageName;
            }

            var processName = new LSA_STRING
            {
                Buffer = processNameStr,
                Length = (ushort)processNameStr.Length,
                MaximumLength = (ushort)processNameStr.Length
            };

            var result = LsaRegisterLogonProcess(ref processName, out LsaSafeHandle lsaHandle, out ulong securityMode);

            LsaThrowIfError(result);

            return new LsaInterop(lsaHandle, package);
        }

        /// <summary>
        /// Create a new instance of the interop as a standard unprivileged caller.
        /// </summary>
        /// <param name="package">The name of the LSA authentication package that will be interacted with.</param>
        /// <returns>Returns an instance of the <see cref="LsaInterop"/> class.</returns>
        public static LsaInterop Connect(string package = KerberosPackageName)
        {
            if (string.IsNullOrWhiteSpace(package))
            {
                package = KerberosPackageName;
            }

            var result = LsaConnectUntrusted(out LsaSafeHandle lsaHandle);

            LsaThrowIfError(result);

            return new LsaInterop(lsaHandle, package);
        }

        /// <summary>
        /// The current LogonId represented by this LSA Handle.
        /// </summary>
        public ulong LogonId => this.luid;

        /// <summary>
        /// Create a "NewCredentials" logon session for the current LSA Handle. This does not authenticate the user
        /// and only uses the credentials provided for outbound calls similar to the /netonly flag for runas.exe.
        ///
        /// Note: this will call <see cref="ImpersonateLoggedOnUser(LsaTokenSafeHandle)" /> and set the current
        /// thread's primary token to the generated NT Token.
        /// </summary>
        /// <param name="username">The username to be used. Note leaving this null will use the default value "user".
        /// Passing an empty string will cause LSA to treat this as an anonymous user.</param>
        /// <param name="password">The password to be used by LSA for any future outbound ticket requests not already cached.</param>
        /// <param name="realm">The default realm to be used by LSA for the any outbound ticket requests not already cached.</param>
        public unsafe void LogonUser(string username = null, string password = null, string realm = null)
        {
            if (username == null)
            {
                username = DefaultUserName;
            }

            if (password == null)
            {
                password = string.Empty;
            }

            if (realm == null)
            {
                realm = string.Empty;
            }

            var originName = new LSA_STRING
            {
                Buffer = ProcessName,
                Length = (ushort)(ProcessName.Length * 2),
                MaximumLength = (ushort)(ProcessName.Length * 2)
            };

            var bufferSize = Marshal.SizeOf(typeof(KERB_INTERACTIVE_LOGON)) +
                (realm.Length * 2) +
                (username.Length * 2) +
                (password.Length * 2);

            if (this.impersonationContext != null)
            {
                this.impersonationContext.Dispose();
                this.impersonationContext = null;
            }

            LsaBufferSafeHandle profileBuffer = null;

            using (var pool = CryptoPool.Rent<byte>(bufferSize))
            {
                var buffer = pool.Memory.Slice(0, bufferSize);

                try
                {
                    fixed (byte* pBuffer = &MemoryMarshal.GetReference(buffer.Span))
                    {
                        KERB_INTERACTIVE_LOGON* pLogon = (KERB_INTERACTIVE_LOGON*)pBuffer;

                        pLogon->MessageType = KERB_LOGON_SUBMIT_TYPE.KerbInteractiveLogon;

                        int offset = Marshal.SizeOf(typeof(KERB_INTERACTIVE_LOGON));

                        SetString(realm, (IntPtr)pLogon, ref pLogon->LogonDomainName, ref offset);
                        SetString(username, (IntPtr)pLogon, ref pLogon->UserName, ref offset);
                        SetString(password, (IntPtr)pLogon, ref pLogon->Password, ref offset);

                        var tokenSource = new TOKEN_SOURCE() { SourceName = Encoding.UTF8.GetBytes("kerb.net") };

                        int profileLength = 0;

                        int result = LsaLogonUser(
                             this.lsaHandle,
                             ref originName,
                             SECURITY_LOGON_TYPE.NewCredentials,
                             this.negotiateAuthPackage,
                             pLogon,
                             bufferSize,
                             IntPtr.Zero,
                             ref tokenSource,
                             out profileBuffer,
                             ref profileLength,
                             out this.luid,
                             out this.impersonationContext,
                             out IntPtr pQuotas,
                             out int subStatus
                         );

                        LsaThrowIfError(result);
                    }
                }
                finally
                {
                    profileBuffer?.Dispose();
                }
            }

            // this call to impersonate will set the current thread token to be the token out of LsaLogonUser
            // do we need to do anything special if this gets used within an async context?

            this.impersonationContext.Impersonate();
        }

        /// <summary>
        /// Purge the ticket cache of the provided Logon Id. Note that the value 0 zero is treated as the current users Logon Id.
        /// </summary>
        /// <param name="luid">The Logon Id of the cache to be purged.</param>
        public unsafe void PurgeTicketCache(long luid = 0)
        {
            var purgeRequest = new KERB_PURGE_TKT_CACHE_EX_REQUEST
            {
                MessageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbPurgeTicketCacheExMessage,
                Flags = 1,
                LogonId = luid
            };

            var bufferSize = Marshal.SizeOf(typeof(KERB_PURGE_TKT_CACHE_EX_REQUEST));

            using (var pool = CryptoPool.Rent<byte>(bufferSize))
            {
                var buffer = pool.Memory.Slice(0, bufferSize);

                fixed (void* pBuffer = &MemoryMarshal.GetReference(buffer.Span))
                {
                    Marshal.StructureToPtr(purgeRequest, (IntPtr)pBuffer, false);

                    this.LsaCallAuthenticationPackage(pBuffer, bufferSize);
                }
            }
        }

        /// <summary>
        /// Import a krb-cred structure containing one or more tickets into the current user ticket cache.
        /// </summary>
        /// <param name="krbCred">The krb-cred to import into the cache.</param>
        /// <param name="luid">The Logon Id of the user owning the ticket cache. The default of 0 represents the currently logged on user.</param>
        public unsafe void ImportCredential(KrbCred krbCred, long luid = 0)
        {
            if (krbCred is null)
            {
                throw new ArgumentNullException(nameof(krbCred));
            }

            var krbCredBytes = krbCred.EncodeApplication();

            var ticketRequest = new KERB_SUBMIT_TKT_REQUEST
            {
                MessageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbSubmitTicketMessage,
                KerbCredSize = krbCredBytes.Length,
                KerbCredOffset = Marshal.SizeOf(typeof(KERB_SUBMIT_TKT_REQUEST)),
                LogonId = luid
            };

            var bufferSize = ticketRequest.KerbCredOffset + krbCredBytes.Length;

            using (var pool = CryptoPool.Rent<byte>(bufferSize))
            {
                var buffer = pool.Memory.Slice(0, bufferSize);

                fixed (void* pBuffer = &MemoryMarshal.GetReference(buffer.Span))
                {
                    Marshal.StructureToPtr(ticketRequest, (IntPtr)pBuffer, false);
                    krbCredBytes.Span.CopyTo(buffer.Span.Slice(ticketRequest.KerbCredOffset));

                    this.LsaCallAuthenticationPackage(pBuffer, bufferSize);
                }
            }
        }

        private unsafe void LsaCallAuthenticationPackage(void* pBuffer, int bufferSize)
        {
            LsaBufferSafeHandle returnBuffer = null;

            try
            {
                var result = NativeMethods.LsaCallAuthenticationPackage(
                    this.lsaHandle,
                    this.selectedAuthPackage,
                    pBuffer,
                    bufferSize,
                    out returnBuffer,
                    out int returnBufferLength,
                    out int protocolStatus
                );

                LsaThrowIfError(result);
                LsaThrowIfError(protocolStatus);
            }
            finally
            {
                returnBuffer?.Dispose();
            }
        }

        private static unsafe void SetString(string value, IntPtr messageBase, ref UNICODE_STRING unicodeString, ref int offset)
        {
            unicodeString = new UNICODE_STRING
            {
                Length = (ushort)(value.Length * 2),
                MaximumLength = (ushort)((value.Length * 2) + 2),
                Buffer = IntPtr.Add(messageBase, offset)
            };

            var buffer = new Span<byte>((void*)unicodeString.Buffer, unicodeString.Length);

            MemoryMarshal.Cast<char, byte>(value.AsSpan()).CopyTo(buffer);

            offset += unicodeString.Length;
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!this.disposedValue)
            {
                if (disposing)
                {
                    this.impersonationContext?.Dispose();
                }

                this.lsaHandle.Dispose();
                this.disposedValue = true;
            }
        }

        ~LsaInterop()
        {
            this.Dispose(disposing: false);
        }

        public void Dispose()
        {
            this.Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }
}
