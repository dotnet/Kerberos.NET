using System;
using System.Runtime.InteropServices;

namespace Kerberos.NET.Win32
{
    public abstract class Credential
    {
        protected const int SEC_WINNT_AUTH_IDENTITY_VERSION_2 = 0x201;

        internal abstract CredentialHandle Structify();

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

        protected override bool ReleaseHandle()
        {
            return true;
        }
    }
}
