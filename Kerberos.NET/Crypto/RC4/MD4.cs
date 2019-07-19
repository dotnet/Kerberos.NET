using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Kerberos.NET.Crypto
{
    public sealed class MD4 : IDisposable
    {
        private const string ADVAPI32 = "advapi32.dll";
        private const int PROV_RSA_AES = 24;
        private const int CRYPT_NEWKEYSET = 0x00000008;
        private const int CALG_MD4 = 0x00008002;
        private const int HP_HASHVAL = 0x0002;

        [DllImport(ADVAPI32, CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool CryptAcquireContext(
            ref IntPtr hProv,
            string pszContainer,
            string pszProvider,
            int dwProvType,
            int dwFlags
        );

        [DllImport(ADVAPI32, CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool CryptCreateHash(
            IntPtr hProv,
            int algId,
            IntPtr hKey,
            int dwFlags,
            ref IntPtr phHash
        );

        [DllImport(ADVAPI32, SetLastError = true)]
        private static extern bool CryptHashData(
            IntPtr hHash,
            byte[] pbData,
            int dataLen,
            int flags
        );

        [DllImport(ADVAPI32, CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool CryptGetHashParam(
            IntPtr hHash,
            int dwParam,
            [Out] byte[] pbData,
            ref int pdwDataLen,
            int dwFlags
        );

        [DllImport(ADVAPI32)]
        private static extern bool CryptReleaseContext(IntPtr hProv, int dwFlags);

        [DllImport(ADVAPI32, SetLastError = true)]
        private static extern bool CryptDestroyHash(IntPtr hHash);

        private readonly IntPtr hProvider;
        private readonly IntPtr hHash;

        public MD4()
        {
            if (!CryptAcquireContext(ref hProvider, "MD4", null, PROV_RSA_AES, 0))
            {
                if (!CryptAcquireContext(ref hProvider, "MD4", null, PROV_RSA_AES, CRYPT_NEWKEYSET))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
            }

            if (!CryptCreateHash(hProvider, CALG_MD4, IntPtr.Zero, 0, ref hHash))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }

        public ReadOnlySpan<byte> ComputeHash(ReadOnlySpan<byte> data)
        {
            if (!CryptHashData(hHash, data.ToArray(), data.Length, 0))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            var hashSize = 16;

            byte[] hashValue = new byte[hashSize];

            if (!CryptGetHashParam(hHash, HP_HASHVAL, hashValue, ref hashSize, 0))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            return new ReadOnlySpan<byte>(hashValue);
        }

        public void Dispose()
        {
            if (hHash != IntPtr.Zero)
            {
                CryptDestroyHash(hHash);
            }

            if (hProvider != IntPtr.Zero)
            {
                CryptReleaseContext(hProvider, 0);
            }
        }
    }
}
