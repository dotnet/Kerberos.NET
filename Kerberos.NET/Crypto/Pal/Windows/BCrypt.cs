// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Concurrent;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Kerberos.NET.Crypto
{
    internal unsafe static class BCrypt
    {
        private const string BCryptLib = "BCrypt.dll";

        private static readonly ConcurrentDictionary<string, IntPtr> AlgorithmProviderCache = new();

        public static IntPtr GetCachedBCryptAlgorithmProvider(string algorithm)
        {
            return AlgorithmProviderCache.GetOrAdd(algorithm, alg => CreateBCryptAlgorithmProvider(alg));
        }

        private static IntPtr CreateBCryptAlgorithmProvider(string algorithm)
        {
            BCryptOpenAlgorithmProvider(out IntPtr phAlgorithm, algorithm);

            return phAlgorithm;
        }

        public static void ThrowIfNotSuccess(NtStatus status)
        {
            if (status != NtStatus.STATUS_SUCCESS)
            {
                throw new Win32Exception((int)status);
            }
        }

        [DllImport(BCryptLib, CharSet = CharSet.Unicode)]
        public static extern NtStatus BCryptOpenAlgorithmProvider(
            out IntPtr phAlgorithm,
            string pszAlgId,
            string pszImplementation = null,
            BCryptOpenAlgorithmProviderFlags dwFlags = BCryptOpenAlgorithmProviderFlags.None
        );

        [DllImport(BCryptLib, CharSet = CharSet.Unicode)]
        public static extern NtStatus BCryptCloseAlgorithmProvider(
            IntPtr hAlgorithm,
            int dwFlags = 0
        );

        [DllImport(BCryptLib, CharSet = CharSet.Unicode)]
        public static extern NtStatus BCryptCreateHash(
            IntPtr hAlgorithm,
            out IntPtr phHash,
            IntPtr pbHashObject,
            int cbHashObject,
            ref byte pbSecret,
            int cbSecrect,
            BCryptCreateHashFlags dwFlags = BCryptCreateHashFlags.None
        );

        [DllImport(BCryptLib, CharSet = CharSet.Unicode)]
        public static extern NtStatus BCryptDestroyHash(
            IntPtr hHash
        );

        [DllImport(BCryptLib, CharSet = CharSet.Unicode)]
        public static extern NtStatus BCryptHashData(
            IntPtr hHash,
            ref byte pbInput,
            int cbInput,
            int dwFlags = 0
        );

        [DllImport(BCryptLib, CharSet = CharSet.Unicode)]
        public static extern NtStatus BCryptFinishHash(
            IntPtr hHash,
            ref byte pbOutput,
            int cbOutput,
            int dwFlags = 0
        );

        [DllImport(BCryptLib, CharSet = CharSet.Unicode)]
        public unsafe static extern NtStatus BCryptSetProperty(
            IntPtr hObject,
            string pszProperty,
            byte* pbInput,
            int cbInput,
            int dwFlags = 0
        );

        [DllImport(BCryptLib, CharSet = CharSet.Unicode)]
        public static extern NtStatus BCryptGenerateKeyPair(
            IntPtr hAlgorithm,
            ref IntPtr hKey,
            int dwLength,
            int dwFlags = 0
        );

        [DllImport(BCryptLib, CharSet = CharSet.Unicode)]
        public static extern NtStatus BCryptFinalizeKeyPair(
            IntPtr hKey,
            int dwFlags = 0
        );

        [DllImport(BCryptLib, CharSet = CharSet.Unicode)]
        public unsafe static extern NtStatus BCryptExportKey(
          IntPtr hKey,
          IntPtr hExportKey,
          string pszBlobType,
          byte* pbOutput,
          int cbOutput,
          out int pcbResult,
          int dwFlags = 0
        );

        [DllImport(BCryptLib, CharSet = CharSet.Unicode)]
        public unsafe static extern NtStatus BCryptImportKeyPair(
           IntPtr hAlgorithm,
           IntPtr hImportKey,
           string pszBlobType,
           ref IntPtr phKey,
           byte* pbInput,
           int cbInput,
           int dwFlags = 0
        );

        [DllImport(BCryptLib, CharSet = CharSet.Unicode)]
        public unsafe static extern NtStatus BCryptDeriveKey(
            IntPtr hSharedSecret,
            string pwszKDF,
            BCryptBufferDesc* pParameterList,
            byte* pbDerivedKey,
            int cbDerivedKey,
            ref int pcbResult,
            int dwFlags = 0
        );

        [DllImport(BCryptLib, CharSet = CharSet.Unicode)]
        public static extern NtStatus BCryptDestroyKey(
           IntPtr hKey
        );

        [DllImport(BCryptLib, CharSet = CharSet.Unicode)]
        public static extern NtStatus BCryptSecretAgreement(
            IntPtr hPrivKey,
            IntPtr hPubKey,
            ref IntPtr phAgreedSecret,
            int dwFlags = 0
        );

        [DllImport(BCryptLib, CharSet = CharSet.Unicode)]
        public static extern NtStatus BCryptDestroySecret(
            IntPtr hSecret
        );

        [StructLayout(LayoutKind.Sequential)]
        public struct BCRYPT_DH_PARAMETER
        {
            public BCRYPT_DH_PARAMETER_HEADER Header;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct BCRYPT_DH_PARAMETER_HEADER
        {
            public int CbLength;
            public int DwMagic;
            public int CbKeyLength;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct BCRYPT_DH_KEY_BLOB
        {
            public BCRYPT_DH_KEY_BLOB_HEADER Header;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct BCRYPT_DH_KEY_BLOB_HEADER
        {
            public int DwMagic;
            public int CbKey;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct BCryptBufferDesc
        {
            public int UlVersion;
            public int CBuffers;
            public IntPtr PBuffers;
        }
    }
}
