using Kerberos.NET.Logging;
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using static Kerberos.NET.Win32.NativeMethods;

namespace Kerberos.NET.Win32
{
    public abstract class Credential
    {
        protected const int SEC_WINNT_AUTH_IDENTITY_VERSION_2 = 0x201;

        internal abstract CredentialHandle Structify();

        protected static unsafe IntPtr PtrIncrement(void* thing, uint offset)
        {
            return IntPtr.Add((IntPtr)thing, (int)offset);
        }

        protected static unsafe void* SafeAlloc(int size)
        {
            var pBytes = (byte*)Marshal.AllocHGlobal(size);

            return MemSet(pBytes, 0, size);
        }

        public static Credential Current()
        {
            return new CurrentCredential();
        }

        private class CurrentCredential : Credential
        {
            internal unsafe override CredentialHandle Structify()
            {
                return new CredentialHandle((void*)0);
            }
        }
    }

    public class CredentialHandle : SafeHandle
    {
        public unsafe CredentialHandle(void* cred)
            : base(new IntPtr(cred), true)
        {
        }

        public override bool IsInvalid => base.handle == IntPtr.Zero;

        private static unsafe void DebugStructure(byte* creds, uint size)
        {
            var bytes = (IntPtr)creds;

            Debug.Write(bytes.DumpHex(size));
        }

        public unsafe void DebugStructure()
        {
#if DEBUG
            if (!IsInvalid)
            {
                SEC_WINNT_AUTH_IDENTITY_EX2* creds = (SEC_WINNT_AUTH_IDENTITY_EX2*)handle;
                DebugStructure((byte*)creds, creds->cbStructureLength);
            }
#endif
        }

        protected override bool ReleaseHandle()
        {
            if (base.handle != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(base.handle);
            }

            base.handle = IntPtr.Zero;

            return true;
        }
    }
}
