// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

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
}