// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Kerberos.NET.Crypto
{
    internal unsafe abstract class Win32CspHash : IHashAlgorithm
    {
        protected Win32CspHash(string algorithm, int calg, int hashSize)
        {
            this.Algorithm = algorithm;
            this.CAlg = calg;
            this.HashSize = hashSize;

            if (!CryptAcquireContext(ref this.hProvider, this.Algorithm, null, PROV_RSA_AES, 0))
            {
                if (!CryptAcquireContext(ref this.hProvider, this.Algorithm, null, PROV_RSA_AES, CRYPT_NEWKEYSET))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
            }

            if (!CryptCreateHash(this.hProvider, this.CAlg, IntPtr.Zero, 0, ref this.hHash))
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
                if (!CryptHashData(this.hHash, pData, data.Length, 0))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
            }

            var hashSize = this.HashSize;

            byte[] hashValue = new byte[hashSize];

            if (!CryptGetHashParam(this.hHash, HP_HASHVAL, hashValue, ref hashSize, 0))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            return new ReadOnlyMemory<byte>(hashValue);
        }

        public void Dispose()
        {
            if (this.hHash != IntPtr.Zero)
            {
                CryptDestroyHash(this.hHash);
            }

            if (this.hProvider != IntPtr.Zero)
            {
                CryptReleaseContext(this.hProvider, 0);
            }
        }
    }
}
