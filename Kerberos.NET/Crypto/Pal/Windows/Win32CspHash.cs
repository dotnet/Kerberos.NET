using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Kerberos.NET.Crypto
{
    internal unsafe abstract class Win32CspHash : IHashAlgorithm
    {
        protected Win32CspHash(string algorithm, int calg, int hashSize)
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

        [DllImport(ADVAPI32, CharSet = CharSet.Unicode, SetLastError = true)]
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

        [DllImport(ADVAPI32, SetLastError = true)]
        private static extern bool CryptGetHashParam(
            IntPtr hHash,
            int dwParam,
            byte* pbData,
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

        public ReadOnlyMemory<byte> ComputeHash(byte[] data) => ComputeHash(data.AsSpan());
        public ReadOnlyMemory<byte> ComputeHash(ReadOnlyMemory<byte> data) => ComputeHash(data.Span);

        public ReadOnlyMemory<byte> ComputeHash(ReadOnlySpan<byte> data)
        {
            byte[] hash = new byte[HashSize];

            ComputeHash(data, hash, out int bytesWritten);
            Debug.Assert(bytesWritten == hash.Length);

            return hash;
        }

        public void ComputeHash(ReadOnlySpan<byte> data, Span<byte> hash, out int bytesWritten)
        {
            fixed (byte* pData = data)
            {
                if (!CryptHashData(hHash, pData, data.Length, 0))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
            }

            Debug.Assert(hash.Length >= HashSize);
            int hashSize = HashSize;

            fixed (byte* pHash = &MemoryMarshal.GetReference(hash))
            {
                if (!CryptGetHashParam(hHash, HP_HASHVAL, pHash, ref hashSize, 0))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                bytesWritten = hashSize;
            }
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
