// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using Kerberos.NET.Client;
using Kerberos.NET.Entities;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
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
            username ??= DefaultUserName;

            if (this.impersonationContext != null)
            {
                this.impersonationContext.Dispose();
                this.impersonationContext = null;
            }

            this.impersonationContext = this.LogonUser(username, password, realm, LogonType.NewCredentials);


            // this call to impersonate will set the current thread token to be the token out of LsaLogonUser
            // do we need to do anything special if this gets used within an async context?

            this.impersonationContext.Impersonate();
        }

        /// <summary>
        /// Create a logon session for the current LSA Handle.
        /// </summary>
        /// <param name="username">The username to be used.
        /// Passing an empty string will cause LSA to treat this as an anonymous user.</param>
        /// <param name="password">The password to be used by LSA for any future outbound ticket requests not already cached.</param>
        /// <param name="realm">The default realm to be used by LSA for the any outbound ticket requests not already cached.</param>
        /// <param name="logonType">The type of logon session to create</param>
        public unsafe LsaTokenSafeHandle LogonUser(
            string username,
            string password,
            string realm,
            LogonType logonType
        )
        {
            username ??= string.Empty;

            password ??= string.Empty;

            realm ??= string.Empty;

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

            LsaTokenSafeHandle tokenHandle = null;
            LsaBufferSafeHandle profileBuffer = null;

            WithFixedBuffer(bufferSize, (p, _) =>
            {
                try
                {
                    var pLogon = (KERB_INTERACTIVE_LOGON*)p;

                    pLogon->MessageType = KERB_LOGON_SUBMIT_TYPE.KerbInteractiveLogon;

                    int offset = Marshal.SizeOf(typeof(KERB_INTERACTIVE_LOGON));

                    SetString(realm, pLogon, ref pLogon->LogonDomainName, ref offset);
                    SetString(username, pLogon, ref pLogon->UserName, ref offset);
                    SetString(password, pLogon, ref pLogon->Password, ref offset);

                    var tokenSource = new TOKEN_SOURCE() { SourceName = Encoding.UTF8.GetBytes("kerb.net") };

                    int profileLength = 0;

                    int result = LsaLogonUser(
                         this.lsaHandle,
                         ref originName,
                         logonType,
                         this.negotiateAuthPackage,
                         pLogon,
                         bufferSize,
                         IntPtr.Zero,
                         ref tokenSource,
                         out profileBuffer,
                         ref profileLength,
                         out this.luid,
                         out tokenHandle,
                         out IntPtr pQuotas,
                         out int subStatus
                     );

                    LsaThrowIfError(result);
                }
                finally
                {
                    profileBuffer?.Dispose();
                }
            });

            return tokenHandle;
        }

        /// <summary>
        /// Purge the ticket cache of the provided Logon Id. Note that the value 0 zero is treated as the current users Logon Id.
        /// </summary>
        /// <param name="luid">The Logon Id of the cache to be purged.</param>
        public unsafe void PurgeTicketCache(long luid = 0)
        {
            WithFixedBuffer(Marshal.SizeOf(typeof(KERB_PURGE_TKT_CACHE_EX_REQUEST)), (p, bufferSize) =>
            {
                var pPurgeRequest = (KERB_PURGE_TKT_CACHE_EX_REQUEST*)p;

                pPurgeRequest->MessageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbPurgeTicketCacheExMessage;
                pPurgeRequest->Flags = 1;
                pPurgeRequest->LogonId = luid;

                this.LsaCallAuthenticationPackage(pPurgeRequest, bufferSize);
            });
        }

        /// <summary>
        /// Get a list of tickets from within the current logon session or that of the passed in LUID.
        /// </summary>
        /// <param name="luid">The Logon Id of the cache to be purged.</param>
        /// <returns>Returns a list of cache entries</returns>
        public unsafe IEnumerable<KerberosClientCacheEntry> GetTicketCache(long luid = 0)
        {
            return WithFixedBuffer(Marshal.SizeOf(typeof(KERB_QUERY_TKT_CACHE_REQUEST)), (p, bufferSize) =>
            {
                var pRequest = (KERB_QUERY_TKT_CACHE_REQUEST*)p;

                pRequest->MessageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbQueryTicketCacheEx3Message;
                pRequest->LogonId = luid;

                var response = this.LsaCallAuthenticationPackageWithReturn(pRequest, bufferSize);

                return WithFixedBuffer(response, p =>
                {
                    var pCacheResponse = (KERB_QUERY_TKT_CACHE_EX3_RESPONSE*)p;

                    var cacheResult = new List<KerberosClientCacheEntry>();

                    for (var i = 0; i < pCacheResponse->CountOfTickets; i++)
                    {
                        var ticket = (&pCacheResponse->Tickets)[i];

                        cacheResult.Add(ticket.ToCacheEntry());
                    }

                    return cacheResult;
                });
            });
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

            var size = Marshal.SizeOf(typeof(KERB_SUBMIT_TKT_REQUEST));

            var krbCredBytes = krbCred.EncodeApplication();

            WithFixedBuffer(size + krbCredBytes.Length, (p, bufferSize) =>
            {
                var pRequest = (KERB_SUBMIT_TKT_REQUEST*)p;

                pRequest->MessageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbSubmitTicketMessage;
                pRequest->KerbCredSize = krbCredBytes.Length;
                pRequest->KerbCredOffset = size;
                pRequest->LogonId = luid;

                krbCredBytes.Span.CopyTo(new Span<byte>(pRequest, bufferSize).Slice(size));

                this.LsaCallAuthenticationPackage(pRequest, bufferSize);
            });
        }

        /// <summary>
        /// Get a Kerberos ticket for the provided SPN from teh current session or that of the passed in LUID.
        /// </summary>
        /// <param name="spn">The SPN to get a ticket against.</param>
        /// <param name="luid">The logon session</param>
        /// <returns>Returns a KrbCred containing the ticket and session key</returns>
        public unsafe KrbCred GetTicket(string spn, long luid = 0)
        {
            if (string.IsNullOrWhiteSpace(spn))
            {
                throw new ArgumentNullException(nameof(spn));
            }

            int requestSize = sizeof(KERB_RETRIEVE_TKT_REQUEST);

            return WithFixedBuffer(
                requestSize + (spn.Length * 2),
                (p, bufferSize) =>
            {
                var pRequest = (KERB_RETRIEVE_TKT_REQUEST*)p;

                pRequest->MessageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbRetrieveEncodedTicketMessage;
                pRequest->LogonId = luid;
                pRequest->CacheOptions = KerberosCacheOptions.KERB_RETRIEVE_TICKET_AS_KERB_CRED;

                SetString(spn, pRequest, ref pRequest->TargetName, ref requestSize);

                var response = this.LsaCallAuthenticationPackageWithReturn(pRequest, bufferSize);

                return WithFixedBuffer(response, p =>
                {
                    var pResponse = (KERB_RETRIEVE_TKT_RESPONSE*)p;

                    var cred = new Span<byte>(pResponse->Ticket.EncodedTicket, pResponse->Ticket.EncodedTicketSize);

                    return KrbCred.DecodeApplication(cred.ToArray());
                });
            });
        }

        private static unsafe TRet WithFixedBuffer<TRet>(LsaBufferSafeHandle handle, Func<IntPtr, TRet> func)
        {
            fixed (void* respBytes = &MemoryMarshal.GetReference(handle.AsSpan()))
            {
                return func((IntPtr)respBytes);
            }
        }

        private static unsafe TRet WithFixedBuffer<TRet>(int bufferSize, Func<IntPtr, int, TRet> func)
        {
            using (var pool = CryptoPool.Rent<byte>(bufferSize))
            {
                var buffer = pool.Memory.Slice(0, bufferSize);

                fixed (void* pBuffer = &MemoryMarshal.GetReference(buffer.Span))
                {
                    return func((IntPtr)pBuffer, bufferSize);
                }
            }
        }

        private static unsafe void WithFixedBuffer(int bufferSize, Action<IntPtr, int> func)
        {
            WithFixedBuffer<object>(bufferSize, (p, s) =>
            {
                func(p, s);

                return null;
            });
        }

        private unsafe void LsaCallAuthenticationPackage(void* pBuffer, int bufferSize)
        {
            LsaBufferSafeHandle returnBuffer = null;

            try
            {
                returnBuffer = LsaCallAuthenticationPackageWithReturn(pBuffer, bufferSize);
            }
            finally
            {
                returnBuffer?.Dispose();
            }
        }

        private unsafe LsaBufferSafeHandle LsaCallAuthenticationPackageWithReturn(void* pBuffer, int bufferSize)
        {
            var result = NativeMethods.LsaCallAuthenticationPackage(
                this.lsaHandle,
                this.selectedAuthPackage,
                pBuffer,
                bufferSize,
                out LsaBufferSafeHandle returnBuffer,
                out int returnBufferLength,
                out int protocolStatus
            );

            LsaThrowIfError(result);
            LsaThrowIfError(protocolStatus);

            returnBuffer.BufferLength = returnBufferLength;

            return returnBuffer;
        }

        private static unsafe void SetString(string value, void* messageBase, ref UNICODE_STRING unicodeString, ref int offset)
        {
            unicodeString = new UNICODE_STRING
            {
                Length = (ushort)(value.Length * 2),
                MaximumLength = (ushort)((value.Length * 2) + 2),
                Buffer = IntPtr.Add((IntPtr)messageBase, offset)
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
