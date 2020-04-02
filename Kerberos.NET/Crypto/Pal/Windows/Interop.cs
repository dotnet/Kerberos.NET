using System;
using System.Runtime.InteropServices;

namespace Kerberos.NET.Crypto.Pal.Windows
{
    internal static unsafe partial class Interop
    {
        private const string ADVAPI32 = "advapi32.dll";

        public const int PROV_RSA_AES = 24;

        public const int HP_HASHVAL = 0x0002;

        [DllImport(ADVAPI32, CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CryptAcquireContext(
            ref IntPtr hProv,
            string pszContainer,
            string pszProvider,
            int dwProvType,
            uint dwFlags
        );

        [DllImport(ADVAPI32, SetLastError = true)]
        public static extern bool CryptCreateHash(
            IntPtr hProv,
            int algId,
            IntPtr hKey,
            int dwFlags,
            ref IntPtr phHash
        );

        [DllImport(ADVAPI32, SetLastError = true)]
        public static extern bool CryptHashData(
            IntPtr hHash,
            byte* pbData,
            int dataLen,
            int flags
        );

        [DllImport(ADVAPI32, SetLastError = true)]
        public static extern bool CryptGetHashParam(
            IntPtr hHash,
            int dwParam,
            byte* pbData,
            ref int pdwDataLen,
            int dwFlags
        );

        [DllImport(ADVAPI32)]
        public static extern bool CryptReleaseContext(IntPtr hProv, int dwFlags);

        [DllImport(ADVAPI32, SetLastError = true)]
        public static extern bool CryptDestroyHash(IntPtr hHash);
    }
}
