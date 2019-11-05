using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Kerberos.NET.Crypto
{
    internal sealed class MD5 : Hash
    {
        private const int CALG_MD5 = 0x00008003;
        private const int MD5HashSize = 16;

        public MD5() : base("MD5", CALG_MD5, MD5HashSize) { }
    }

    internal sealed class MD4 : Hash
    {
        private const int CALG_MD4 = 0x00008002;
        private const int MD4HashSize = 16;

        public MD4() : base("MD4", CALG_MD4, MD4HashSize) { }
    }

    internal unsafe abstract class Hash : IDisposable
    {
        protected Hash(string algorithm, int calg, int hashSize)
        {
            Algorithm = algorithm;
            CAlg = calg;
            HashSize = hashSize;

            if (!CryptAcquireContext(ref hProvider, Algorithm, null, PROV_RSA_AES, 0))
            {
                if (!CryptAcquireContext(ref hProvider, Algorithm, null, PROV_RSA_AES, CRYPT_NEWKEYSET))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
            }

            if (!CryptCreateHash(hProvider, CAlg, IntPtr.Zero, 0, ref hHash))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }

        private const string ADVAPI32 = "advapi32.dll";
        private const int PROV_RSA_AES = 24;
        private const int CRYPT_NEWKEYSET = 0x00000008;

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
            byte* pbData,
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

        public string Algorithm { get; }

        public int CAlg { get; }

        public int HashSize { get; }

        public ReadOnlyMemory<byte> ComputeHash(ReadOnlySpan<byte> data)
        {
            fixed (byte* pData = data)
            {
                if (!CryptHashData(hHash, pData, data.Length, 0))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
            }

            var hashSize = HashSize;

            byte[] hashValue = new byte[hashSize];

            if (!CryptGetHashParam(hHash, HP_HASHVAL, hashValue, ref hashSize, 0))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            return new ReadOnlyMemory<byte>(hashValue);
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
