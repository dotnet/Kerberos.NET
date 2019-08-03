using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

namespace Kerberos.NET.Win32
{
    internal unsafe class NativeMethods
    {
        private const string SECUR32 = "secur32.dll";

        [DllImport(SECUR32,
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

        [DllImport(SECUR32,
                EntryPoint = "InitializeSecurityContext",
                CharSet = CharSet.Auto,
                BestFitMapping = false,
                ThrowOnUnmappableChar = true,
                SetLastError = true)]
        internal static extern SecStatus InitializeSecurityContext_0(
            ref SECURITY_HANDLE phCredential,
            IntPtr phContext,
            string pszTargetName,
            ContextFlag fContextReq,
            int Reserved1,
            int TargetDataRep,
            IntPtr pInput,
            int Reserved2,
            ref SECURITY_HANDLE phNewContext,
            ref SecBufferDesc pOutput,
            out ContextFlag pfContextAttr,
            IntPtr ptsExpiry
        );

        [DllImport(SECUR32,
                EntryPoint = "InitializeSecurityContext",
                CharSet = CharSet.Auto,
                BestFitMapping = false,
                ThrowOnUnmappableChar = true,
                SetLastError = true)]
        internal static extern SecStatus InitializeSecurityContext_1(
            ref SECURITY_HANDLE phCredential,
            ref SECURITY_HANDLE phContext,
            string pszTargetName,
            ContextFlag fContextReq,
            int Reserved1,
            int TargetDataRep,
            ref SecBufferDesc pInput,
            int Reserved2,
            ref SECURITY_HANDLE phNewContext,
            ref SecBufferDesc pOutput,
            out ContextFlag pfContextAttr,
            ref IntPtr ptsExpiry
        );

        [DllImport(SECUR32, SetLastError = true, EntryPoint = "AcceptSecurityContext")]
        internal static extern SecStatus AcceptSecurityContext_0(
            ref SECURITY_HANDLE phCredential,
            IntPtr phContext,
            ref SecBufferDesc pInput,
            ContextFlag fContextReq,
            uint TargetDataRep,
            ref SECURITY_HANDLE phNewContext,
            out SecBufferDesc pOutput,
            out ContextFlag pfContextAttr,
            out SECURITY_INTEGER ptsTimeStamp
        );

        [DllImport(SECUR32, SetLastError = true, EntryPoint = "AcceptSecurityContext")]
        internal static extern SecStatus AcceptSecurityContext_1(
            ref SECURITY_HANDLE phCredential,
            ref SECURITY_HANDLE phContext,
            ref SecBufferDesc pInput,
            ContextFlag fContextReq,
            uint TargetDataRep,
            ref SECURITY_HANDLE phNewContext,
            out SecBufferDesc pOutput,
            out ContextFlag pfContextAttr,
            out SECURITY_INTEGER ptsTimeStamp
        );

        [DllImport(SECUR32, SetLastError = true, EntryPoint = "QueryContextAttributes", CharSet = CharSet.Unicode)]
        internal static extern SecStatus QueryContextAttributesString(
            ref SECURITY_HANDLE phContext,
            SecurityContextAttribute ulAttribute,
            ref SecPkgContext_SecString pBuffer
        );
        
        [DllImport(SECUR32)]
        internal static extern int FreeCredentialsHandle(SECURITY_HANDLE* handle);

        [DllImport(SECUR32)]
        internal static extern int FreeContextBuffer(void* handle);

        [DllImport(SECUR32)]
        public static extern SecStatus DeleteSecurityContext(SECURITY_HANDLE* context);

        internal enum SecBufferType
        {
            SECBUFFER_VERSION = 0,
            SECBUFFER_EMPTY = 0,
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
                cbBuffer = bufferSize;
                BufferType = SecBufferType.SECBUFFER_TOKEN;
                pvBuffer = Marshal.AllocHGlobal(bufferSize);
            }

            public SecBuffer(byte[] secBufferBytes)
                : this(secBufferBytes.Length)
            {
                Marshal.Copy(secBufferBytes, 0, pvBuffer, cbBuffer);
            }

            public void Dispose()
            {
                if (pvBuffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(pvBuffer);
                    pvBuffer = IntPtr.Zero;
                }
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct SecBufferDesc : IDisposable
        {
            private SecBufferType ulVersion;
            public int cBuffers;
            public IntPtr pBuffers; //Point to SecBuffer

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
                ulVersion = SecBufferType.SECBUFFER_VERSION;

                cBuffers = 1;

                pBuffers = Marshal.AllocHGlobal(Marshal.SizeOf(secBuffer));

                Marshal.StructureToPtr(secBuffer, pBuffers, false);
            }

            public void Dispose()
            {
                if (pBuffers != IntPtr.Zero)
                {
                    ForEachBuffer(thisSecBuffer => thisSecBuffer.Dispose());

                    // Freeing pBuffers

                    Marshal.FreeHGlobal(pBuffers);
                    pBuffers = IntPtr.Zero;
                }
            }

            private void ForEachBuffer(Action<SecBuffer> onBuffer)
            {
                for (int Index = 0; Index < cBuffers; Index++)
                {
                    int CurrentOffset = Index * Marshal.SizeOf(typeof(SecBuffer));

                    SecBuffer thisSecBuffer = (SecBuffer)Marshal.PtrToStructure(
                        IntPtr.Add(
                            pBuffers,
                            CurrentOffset
                        ),
                        typeof(SecBuffer)
                    );

                    onBuffer(thisSecBuffer);
                }
            }

            public byte[] ReadBytes()
            {
                if (cBuffers <= 0)
                {
                    return new byte[0];
                }

                var bufferList = new List<byte[]>();

                ForEachBuffer(thisSecBuffer =>
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

                var finalBuffer = new byte[finalLen];

                var position = 0;

                for (var i = 0; i < bufferList.Count; i++)
                {
                    Buffer.BlockCopy(bufferList[i], 0, finalBuffer, position, bufferList[i].Length);

                    position += bufferList[i].Length - 1;
                }

                return finalBuffer;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct SECURITY_HANDLE
        {
            public ulong dwLower;
            public ulong dwUpper;

            public bool IsSet { get { return dwLower > 0 || dwUpper > 0; } }
        };

        [StructLayout(LayoutKind.Sequential)]
        internal struct SECURITY_INTEGER
        {
            public uint LowPart;
            public int HighPart;
        };

        [StructLayout(LayoutKind.Sequential)]
        internal struct SecPkgContext_SecString
        {
            public void* sValue;
        }
    }
}
