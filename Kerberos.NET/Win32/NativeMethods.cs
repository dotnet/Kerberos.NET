// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using Kerberos.NET.Client;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;

namespace Kerberos.NET.Win32
{
    public enum LogonType
    {
        UndefinedLogonType = 0,
        Interactive = 2,
        Network,
        Batch,
        Service,
        Proxy,
        Unlock,
        NetworkCleartext,
        NewCredentials,
        RemoteInteractive,
        CachedInteractive,
        CachedRemoteInteractive,
        CachedUnlock
    }

    internal unsafe class NativeMethods
    {
        private const string SECUR32 = "secur32.dll";
        private const string ADVAPI32 = "advapi32.dll";
        private const string KERNEL32 = "kernel32.dll";

        [DllImport(
            SECUR32,
            CharSet = CharSet.Auto,
            BestFitMapping = false,
            ThrowOnUnmappableChar = true,
            EntryPoint = "AcquireCredentialsHandle")]
        internal static extern SecStatus AcquireCredentialsHandle(
            string pszPrincipal,
            string pszPackage,
            int fCredentialUse,
            IntPtr PAuthenticationID,
            void* pAuthData,
            IntPtr pGetKeyFn,
            IntPtr pvGetKeyArgument,
            ref SECURITY_HANDLE phCredential,
            IntPtr ptsExpiry
        );

        [DllImport(
            SECUR32,
            EntryPoint = "InitializeSecurityContext",
            CharSet = CharSet.Auto,
            BestFitMapping = false,
            ThrowOnUnmappableChar = true,
            SetLastError = true)]
        internal static extern SecStatus InitializeSecurityContext_0(
            ref SECURITY_HANDLE phCredential,
            IntPtr phContext,
            string pszTargetName,
            InitContextFlag fContextReq,
            int Reserved1,
            int TargetDataRep,
            IntPtr pInput,
            int Reserved2,
            ref SECURITY_HANDLE phNewContext,
            ref SecBufferDesc pOutput,
            out InitContextFlag pfContextAttr,
            IntPtr ptsExpiry
        );

        [DllImport(
            SECUR32,
            EntryPoint = "InitializeSecurityContext",
            CharSet = CharSet.Auto,
            BestFitMapping = false,
            ThrowOnUnmappableChar = true,
            SetLastError = true)]
        internal static extern SecStatus InitializeSecurityContext_1(
            ref SECURITY_HANDLE phCredential,
            ref SECURITY_HANDLE phContext,
            string pszTargetName,
            InitContextFlag fContextReq,
            int Reserved1,
            int TargetDataRep,
            ref SecBufferDesc pInput,
            int Reserved2,
            ref SECURITY_HANDLE phNewContext,
            ref SecBufferDesc pOutput,
            out InitContextFlag pfContextAttr,
            ref IntPtr ptsExpiry
        );

        [DllImport(SECUR32, SetLastError = true, EntryPoint = "AcceptSecurityContext")]
        internal static extern SecStatus AcceptSecurityContext_0(
            ref SECURITY_HANDLE phCredential,
            IntPtr phContext,
            ref SecBufferDesc pInput,
            AcceptContextFlag fContextReq,
            uint TargetDataRep,
            ref SECURITY_HANDLE phNewContext,
            out SecBufferDesc pOutput,
            out AcceptContextFlag pfContextAttr,
            out SECURITY_INTEGER ptsTimeStamp
        );

        [DllImport(SECUR32, SetLastError = true, EntryPoint = "AcceptSecurityContext")]
        internal static extern SecStatus AcceptSecurityContext_1(
            ref SECURITY_HANDLE phCredential,
            ref SECURITY_HANDLE phContext,
            ref SecBufferDesc pInput,
            AcceptContextFlag fContextReq,
            uint TargetDataRep,
            ref SECURITY_HANDLE phNewContext,
            out SecBufferDesc pOutput,
            out AcceptContextFlag pfContextAttr,
            out SECURITY_INTEGER ptsTimeStamp
        );

        [DllImport(SECUR32, SetLastError = true, EntryPoint = "QueryContextAttributes", CharSet = CharSet.Unicode)]
        internal static extern SecStatus QueryContextAttributesString(
            ref SECURITY_HANDLE phContext,
            SecurityContextAttribute ulAttribute,
            ref SecPkgContext_SecString pBuffer
        );

        [DllImport(SECUR32, SetLastError = true, EntryPoint = "QueryContextAttributes", CharSet = CharSet.Unicode)]
        internal static extern SecStatus QueryContextAttributesSession(
            ref SECURITY_HANDLE phContext,
            SecurityContextAttribute ulAttribute,
            ref SecPkgContext_SessionKey pBuffer
        );

        [DllImport(SECUR32)]
        internal static extern uint FreeCredentialsHandle(SECURITY_HANDLE* handle);

        [DllImport(SECUR32)]
        internal static extern uint FreeContextBuffer(void* handle);

        [DllImport(SECUR32)]
        public static extern SecStatus DeleteSecurityContext(SECURITY_HANDLE* context);

        [DllImport(SECUR32)]
        public static unsafe extern int LsaCallAuthenticationPackage(
            LsaSafeHandle LsaHandle,
            int AuthenticationPackage,
            void* ProtocolSubmitBuffer,
            int SubmitBufferLength,
            out LsaBufferSafeHandle ProtocolReturnBuffer,
            out int ReturnBufferLength,
            out int ProtocolStatus
        );

        [DllImport(SECUR32)]
        public static extern int LsaConnectUntrusted(
           [Out] out LsaSafeHandle LsaHandle
        );

        [DllImport(SECUR32)]
        public static extern int LsaRegisterLogonProcess(
            ref LSA_STRING LogonProcessName,
            out LsaSafeHandle LsaHandle,
            out ulong SecurityMode
        );

        [DllImport(SECUR32)]
        public static extern int LsaDeregisterLogonProcess(
            IntPtr LsaHandle
        );

        [DllImport(SECUR32)]
        public static extern int LsaLookupAuthenticationPackage(
            LsaSafeHandle LsaHandle,
            ref LSA_STRING PackageName,
            out int AuthenticationPackage
        );

        [DllImport(ADVAPI32)]
        public static extern int LsaNtStatusToWinError(int Status);

        [DllImport(SECUR32)]
        public static extern int LsaFreeReturnBuffer(IntPtr Buffer);

        [DllImport(SECUR32)]
        public static extern int LsaLogonUser(
          LsaSafeHandle LsaHandle,
          ref LSA_STRING OriginName,
          LogonType LogonType,
          int AuthenticationPackage,
          void* AuthenticationInformation,
          int AuthenticationInformationLength,
          IntPtr LocalGroups,
          ref TOKEN_SOURCE SourceContext,
          out LsaBufferSafeHandle ProfileBuffer,
          ref int ProfileBufferLength,
          out LUID LogonId,
          out LsaTokenSafeHandle Token,
          out IntPtr Quotas,
          out int SubStatus
        );

        [DllImport(KERNEL32)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport(ADVAPI32)]
        public static extern bool ImpersonateLoggedOnUser(LsaTokenSafeHandle hToken);

        [DllImport(ADVAPI32)]
        public static extern bool RevertToSelf();

        public static void LsaThrowIfError(int result)
        {
            if (result != 0)
            {
                result = LsaNtStatusToWinError(result);

                throw new Win32Exception(result);
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_INTERACTIVE_LOGON
        {
            public KERB_LOGON_SUBMIT_TYPE MessageType;
            public UNICODE_STRING LogonDomainName;
            public UNICODE_STRING UserName;
            public UNICODE_STRING Password;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_SOURCE
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public byte[] SourceName; // TOKEN_SOURCE_LENGTH
            public LUID SourceIdentifier;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_S4U_LOGON
        {
            public KERB_LOGON_SUBMIT_TYPE MessageType;
            public S4uFlags Flags;
            public UNICODE_STRING ClientUpn;
            public UNICODE_STRING ClientRealm;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;

            public override string ToString()
            {
                return Marshal.PtrToStringUni(this.Buffer, this.Length / 2);
            }
        }

        [Flags]
        public enum S4uFlags
        {
            KERB_S4U_LOGON_FLAG_CHECK_LOGONHOURS = 0x2,
            KERB_S4U_LOGON_FLAG_IDENTIFY = 0x8
        }

        public enum KERB_LOGON_SUBMIT_TYPE
        {
            KerbInteractiveLogon = 2,
            KerbSmartCardLogon = 6,
            KerbWorkstationUnlockLogon = 7,
            KerbSmartCardUnlockLogon = 8,
            KerbProxyLogon = 9,
            KerbTicketLogon = 10,
            KerbTicketUnlockLogon = 11,
            KerbS4ULogon = 12,
            KerbCertificateLogon = 13,
            KerbCertificateS4ULogon = 14,
            KerbCertificateUnlockLogon = 15,
            KerbNoElevationLogon = 83,
            KerbLuidLogon = 84,
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct LSA_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public string Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct LUID
        {
            public uint LowPart;
            public int HighPart;

            public static implicit operator ulong(LUID luid)
            {
                ulong val = (ulong)luid.HighPart << 32;

                return val + luid.LowPart;
            }

            public static implicit operator LUID(long luid)
            {
                return new LUID
                {
                    LowPart = (UInt32)(luid & 0xffffffffL),
                    HighPart = (Int32)(luid >> 32)
                };
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_QUERY_TKT_CACHE_REQUEST
        {
            public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
            public LUID LogonId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct KERB_QUERY_TKT_CACHE_EX3_RESPONSE
        {
            public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
            public int CountOfTickets;
            public KERB_TICKET_CACHE_INFO_EX3 Tickets;
        }

        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct KERB_TICKET_CACHE_INFO_EX3
        {
            public UNICODE_STRING ClientName;
            public UNICODE_STRING ClientRealm;
            public UNICODE_STRING ServerName;
            public UNICODE_STRING ServerRealm;
            public long StartTime;
            public long EndTime;
            public long RenewTime;
            public int EncryptionType;
            public int TicketFlags;
            public int SessionKeyType;
            public int BranchId;
            public int CacheFlags;
            public UNICODE_STRING KdcCalled;

            public KerberosClientCacheEntry ToCacheEntry() => new()
            {
                AuthTime = DateTimeOffset.FromFileTime(this.StartTime),
                StartTime = DateTimeOffset.FromFileTime(this.StartTime),
                EndTime = DateTimeOffset.FromFileTime(this.EndTime),
                Flags = (TicketFlags)this.TicketFlags,
                RenewTill = DateTimeOffset.FromFileTime(this.RenewTime),
                SName = KrbPrincipalName.FromString(this.ServerName.ToString()),
                SessionKey = new KrbEncryptionKey { EType = (EncryptionType)this.SessionKeyType },
                BranchId = this.BranchId,
                KdcCalled = this.KdcCalled.ToString(),
                CacheFlags = this.CacheFlags,
                KdcResponse = new KrbKdcRep
                {
                    CRealm = this.ClientRealm.ToString(),
                    CName = KrbPrincipalName.FromString(this.ClientName.ToString()),
                    Ticket = new KrbTicket
                    {
                        SName = KrbPrincipalName.FromString(this.ServerName.ToString()),
                        Realm = this.ServerRealm.ToString(),
                        EncryptedPart = new KrbEncryptedData { EType = (EncryptionType)this.EncryptionType }
                    }
                }
            };
        }

        public enum KerberosCacheOptions
        {
            /// <summary>
            /// Always request a new ticket; do not search the cache.
            /// If a ticket is obtained, the Kerberos authentication package returns STATUS_SUCCESS in the ProtocolStatus parameter of the LsaCallAuthenticationPackage function.
            /// </summary>
            KERB_RETRIEVE_TICKET_DONT_USE_CACHE = 1,

            /// <summary>
            /// Return only a previously cached ticket.
            /// If such a ticket is not found, the Kerberos authentication package returns STATUS_OBJECT_NAME_NOT_FOUND in the ProtocolStatus parameter of the LsaCallAuthenticationPackage function.
            /// </summary>
            KERB_RETRIEVE_TICKET_USE_CACHE_ONLY = 2,

            /// <summary>
            /// Use the CredentialsHandle member instead of LogonId to identify the logon session. The credential handle is used as the client credential for which the ticket is retrieved
            /// Note This option is not available for 32-bit Windows-based applications running on 64-bit Windows.
            /// </summary>
            KERB_RETRIEVE_TICKET_USE_CREDHANDLE = 4,

            /// <summary>
            /// Return the ticket as a Kerberos credential. The Kerberos ticket is defined in Internet RFC 4120 as KRB_CRED. For more information, see http://www.ietf.org.
            /// </summary>
            KERB_RETRIEVE_TICKET_AS_KERB_CRED = 8,

            /// <summary>
            /// Not implemented.
            /// </summary>
            KERB_RETRIEVE_TICKET_WITH_SEC_CRED = 10,

            /// <summary>
            /// Return the ticket that is currently in the cache. If the ticket is not in the cache, it is requested and then cached.
            /// This flag should not be used with the KERB_RETRIEVE_TICKET_DONT_USE_CACHE flag.
            /// Windows XP with SP1 and earlier and Windows Server 2003:  This option is not available.
            /// </summary>
            KERB_RETRIEVE_TICKET_CACHE_TICKET = 20,

            /// <summary>
            /// Return a fresh ticket with maximum allowed time by the policy. The ticker is cached afterwards.
            /// Use of this flag implies that KERB_RETRIEVE_TICKET_USE_CACHE_ONLY is not set and KERB_RETRIEVE_TICKET_CACHE_TICKET is set.
            /// Windows Vista, Windows Server 2008, Windows XP with SP1 and earlier and Windows Server 2003:  This option is not available.
            /// </summary>
            KERB_RETRIEVE_TICKET_MAX_LIFETIME = 40,
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_RETRIEVE_TKT_REQUEST
        {
            public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
            public LUID LogonId;
            public UNICODE_STRING TargetName;
            public int TicketFlags;
            public KerberosCacheOptions CacheOptions;
            public int EncryptionType;
            public SECURITY_HANDLE CredentialsHandle;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_RETRIEVE_TKT_RESPONSE
        {
            public KERB_EXTERNAL_TICKET Ticket;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_EXTERNAL_TICKET
        {
            public IntPtr ServiceName;
            public IntPtr TargetName;
            public IntPtr ClientName;
            public UNICODE_STRING DomainName;
            public UNICODE_STRING TargetDomainName;
            public UNICODE_STRING AltTargetDomainName;
            public KERB_CRYPTO_KEY SessionKey;
            public int TicketFlags;
            public int Flags;
            public long KeyExpirationTime;
            public long StartTime;
            public long EndTime;
            public long RenewUntil;
            public long TimeSkew;
            public int EncodedTicketSize;
            public void* EncodedTicket;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_CRYPTO_KEY
        {
            public int KeyType;
            public int Length;
            public IntPtr Value;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_SUBMIT_TKT_REQUEST
        {
            public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
            public LUID LogonId;
            public int Flags;
            public KERB_CRYPTO_KEY32 Key;
            public int KerbCredSize;
            public int KerbCredOffset;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_PURGE_TKT_CACHE_EX_REQUEST
        {
            public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
            public LUID LogonId;
            public int Flags;
            public KERB_TICKET_CACHE_INFO_EX TicketTemplate;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_TICKET_CACHE_INFO_EX
        {
            public UNICODE_STRING ClientName;
            public UNICODE_STRING ClientRealm;
            public UNICODE_STRING ServerName;
            public UNICODE_STRING ServerRealm;
            public long StartTime;
            public long EndTime;
            public long RenewTime;
            public int EncryptionType;
            public int TicketFlags;
        }

        public enum KERB_PROTOCOL_MESSAGE_TYPE : UInt32
        {
            KerbDebugRequestMessage = 0,
            KerbQueryTicketCacheMessage,
            KerbChangeMachinePasswordMessage,
            KerbVerifyPacMessage,
            KerbRetrieveTicketMessage,
            KerbUpdateAddressesMessage,
            KerbPurgeTicketCacheMessage,
            KerbChangePasswordMessage,
            KerbRetrieveEncodedTicketMessage,
            KerbDecryptDataMessage,
            KerbAddBindingCacheEntryMessage,
            KerbSetPasswordMessage,
            KerbSetPasswordExMessage,
            KerbVerifyCredentialsMessage,
            KerbQueryTicketCacheExMessage,
            KerbPurgeTicketCacheExMessage,
            KerbRefreshSmartcardCredentialsMessage,
            KerbAddExtraCredentialsMessage,
            KerbQuerySupplementalCredentialsMessage,
            KerbTransferCredentialsMessage,
            KerbQueryTicketCacheEx2Message,
            KerbSubmitTicketMessage,
            KerbAddExtraCredentialsExMessage,
            KerbQueryKdcProxyCacheMessage,
            KerbPurgeKdcProxyCacheMessage,
            KerbQueryTicketCacheEx3Message,
            KerbCleanupMachinePkinitCredsMessage,
            KerbAddBindingCacheEntryExMessage,
            KerbQueryBindingCacheMessage,
            KerbPurgeBindingCacheMessage,
            KerbPinKdcMessage,
            KerbUnpinAllKdcsMessage,
            KerbQueryDomainExtendedPoliciesMessage,
            KerbQueryS4U2ProxyCacheMessage,
            KerbRetrieveKeyTabMessage,
            KerbRefreshPolicyMessage
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_CRYPTO_KEY32
        {
            public int KeyType;
            public int Length;
            public int Offset;
        }

        internal enum SecBufferType
        {
            SECBUFFER_VERSION = 0,
            SECBUFFER_DATA = 1,
            SECBUFFER_TOKEN = 2
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct SecBuffer
        {
            public int cbBuffer;
            public SecBufferType BufferType;
            public IntPtr pvBuffer;

            public SecBuffer(int bufferSize)
            {
                this.cbBuffer = bufferSize;
                this.BufferType = SecBufferType.SECBUFFER_TOKEN;
                this.pvBuffer = Marshal.AllocHGlobal(bufferSize);
            }

            public SecBuffer(byte[] secBufferBytes)
                : this(secBufferBytes.Length)
            {
                Marshal.Copy(secBufferBytes, 0, this.pvBuffer, this.cbBuffer);
            }

            public void Dispose()
            {
                if (this.pvBuffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(this.pvBuffer);
                    this.pvBuffer = IntPtr.Zero;
                }
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct SecBufferDesc : IDisposable
        {
            private readonly SecBufferType ulVersion;
            public int cBuffers;
            public IntPtr pBuffers; // Point to SecBuffer

            public SecBufferDesc(int bufferSize)
                : this(new SecBuffer(bufferSize))
            {
            }

            public SecBufferDesc(byte[] secBufferBytes)
                : this(new SecBuffer(secBufferBytes))
            {
            }

            private SecBufferDesc(SecBuffer secBuffer)
            {
                this.ulVersion = SecBufferType.SECBUFFER_VERSION;

                this.cBuffers = 1;

                this.pBuffers = Marshal.AllocHGlobal(Marshal.SizeOf(secBuffer));

                Marshal.StructureToPtr(secBuffer, this.pBuffers, false);
            }

            public void Dispose()
            {
                if (this.pBuffers != IntPtr.Zero)
                {
                    this.ForEachBuffer(thisSecBuffer => thisSecBuffer.Dispose());

                    // Freeing pBuffers

                    Marshal.FreeHGlobal(this.pBuffers);
                    this.pBuffers = IntPtr.Zero;
                }
            }

            private void ForEachBuffer(Action<SecBuffer> onBuffer)
            {
                for (int Index = 0; Index < this.cBuffers; Index++)
                {
                    int CurrentOffset = Index * Marshal.SizeOf(typeof(SecBuffer));

                    SecBuffer thisSecBuffer = (SecBuffer)Marshal.PtrToStructure(
                        IntPtr.Add(
                            this.pBuffers,
                            CurrentOffset
                        ),
                        typeof(SecBuffer)
                    );

                    onBuffer(thisSecBuffer);
                }
            }

            public byte[] ReadBytes()
            {
                if (this.cBuffers <= 0)
                {
                    return Array.Empty<byte>();
                }

                var bufferList = new List<byte[]>();

                this.ForEachBuffer(thisSecBuffer =>
                {
                    if (thisSecBuffer.cbBuffer <= 0)
                    {
                        return;
                    }

                    var buffer = new byte[thisSecBuffer.cbBuffer];

                    Marshal.Copy(thisSecBuffer.pvBuffer, buffer, 0, thisSecBuffer.cbBuffer);

                    bufferList.Add(buffer);
                });

                var finalLen = bufferList.Sum(b => b.Length);

                var finalBuffer = new Span<byte>(new byte[finalLen]);

                var position = 0;

                for (var i = 0; i < bufferList.Count; i++)
                {
                    bufferList[i].CopyTo(finalBuffer.Slice(position, bufferList[i].Length));

                    position += bufferList[i].Length - 1;
                }

                return finalBuffer.ToArray();
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct SECURITY_HANDLE
        {
            public ulong dwLower;
            public ulong dwUpper;

            public bool IsSet => this.dwLower > 0 || this.dwUpper > 0;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct SECURITY_INTEGER
        {
            public uint LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct SecPkgContext_SecString
        {
            public void* sValue;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal unsafe struct SecPkgContext_SessionKey
        {
            public uint SessionKeyLength;
            public void* SessionKey;
        }
    }
}
