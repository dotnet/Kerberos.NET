using System;
using System.ComponentModel;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

namespace Fiddler.Kerberos.NET
{
    [Flags]
    public enum CredentialFlag
    {
        CREDUIWIN_GENERIC = 0x1,
        CREDUIWIN_CHECKBOX = 0x2,
        CREDUIWIN_AUTHPACKAGE_ONLY = 0x10,
        CREDUIWIN_IN_CRED_ONLY = 0x20,
        CREDUIWIN_ENUMERATE_ADMINS = 0x100,
        CREDUIWIN_ENUMERATE_CURRENT_USER = 0x200,
        CREDUIWIN_SECURE_PROMPT = 0x1000,
        CREDUIWIN_PACK_32_WOW = 0x10000000,
    }

    public static class CredUI
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct CREDUI_INFO
        {
            public int cbSize;
            public IntPtr hwndParent;
            public string pszMessageText;
            public string pszCaptionText;
            public IntPtr hbmBanner;
        }

        [DllImport("credui.dll", CharSet = CharSet.Auto)]
        public static extern int CredUIPromptForWindowsCredentials(
            ref CREDUI_INFO uiInfo,
            int authError,
            ref uint authPackage,
            IntPtr InAuthBuffer,
            uint InAuthBufferSize,
            out IntPtr refOutAuthBuffer,
            out uint refOutAuthBufferSize,
            ref bool fSave,
            CredentialFlag flags
        );

        [DllImport("credui.dll", CharSet = CharSet.Auto)]
        private static extern bool CredUnPackAuthenticationBuffer(int dwFlags,
            IntPtr pAuthBuffer,
            uint cbAuthBuffer,
            StringBuilder pszUserName,
            ref int pcchMaxUserName,
            StringBuilder pszDomainName,
            ref int pcchMaxDomainame,
            StringBuilder pszPassword,
            ref int pcchMaxPassword
        );

        public static NetworkCredential Prompt(string caption, string message)
        {
            var uiInfo = new CREDUI_INFO()
            {
                pszCaptionText = caption,
                pszMessageText = message
            };

            uiInfo.cbSize = Marshal.SizeOf(uiInfo);

            uint authPackage = 0;

            var save = false;

            CredUIPromptForWindowsCredentials(
                ref uiInfo,
                0,
                ref authPackage,
                IntPtr.Zero,
                0,
                out IntPtr outCredBuffer,
                out uint outCredSize,
                ref save,
                CredentialFlag.CREDUIWIN_GENERIC
            );

            if (outCredBuffer == IntPtr.Zero)
            {
                return null;
            }

            var pszUserName = new StringBuilder(100);
            int usernameSize = 100;

            var pszDomainName = new StringBuilder(100);
            int domainSize = 100;

            var pszPassword = new StringBuilder(100);
            int passwordSize = 100;

            try
            {
                if (!CredUnPackAuthenticationBuffer(0, outCredBuffer, outCredSize, pszUserName, ref usernameSize, pszDomainName, ref domainSize, pszPassword, ref passwordSize))
                {
                    var err = new Win32Exception(Marshal.GetLastWin32Error());

                    throw err;
                }

                return new NetworkCredential(pszUserName.ToString(), pszPassword.ToString(), pszDomainName.ToString());
            }
            finally
            {
                Marshal.ZeroFreeGlobalAllocUnicode(outCredBuffer);
            }
        }
    }
}
