using System;
using System.Runtime.InteropServices;

namespace Kerberos.NET.Crypto.Pal.Windows
{
    internal static partial class Interop
    {
        private const string BCryptLib = "BCrypt.dll";

        [DllImport(BCryptLib, CharSet = CharSet.Unicode)]
        public static extern NTSTATUS BCryptOpenAlgorithmProvider(
            out IntPtr phAlgorithm,
            string pszAlgId,
            string pszImplementation = null,
            BCryptOpenAlgorithmProviderFlags dwFlags = BCryptOpenAlgorithmProviderFlags.None
        );

        [DllImport(BCryptLib, CharSet = CharSet.Unicode)]
        public static extern NTSTATUS BCryptCloseAlgorithmProvider(
            IntPtr hAlgorithm,
            int dwFlags = 0
        );

        [DllImport(BCryptLib, CharSet = CharSet.Unicode)]
        public static extern NTSTATUS BCryptCreateHash(
            IntPtr hAlgorithm,
            out IntPtr phHash,
            IntPtr pbHashObject,
            int cbHashObject,
            ref byte pbSecret,
            int cbSecrect,
            BCryptCreateHashFlags dwFlags = BCryptCreateHashFlags.None
        );

        [DllImport(BCryptLib, CharSet = CharSet.Unicode)]
        public static extern NTSTATUS BCryptDestroyHash(
            IntPtr hHash
        );

        [DllImport(BCryptLib, CharSet = CharSet.Unicode)]
        public static extern NTSTATUS BCryptHashData(
            IntPtr hHash,
            ref byte pbInput,
            int cbInput,
            int dwFlags = 0
        );

        [DllImport(BCryptLib, CharSet = CharSet.Unicode)]
        public static extern NTSTATUS BCryptFinishHash(
            IntPtr hHash,
            ref byte pbOutput,
            int cbOutput,
            int dwFlags = 0
        );

        [DllImport(BCryptLib, CharSet = CharSet.Unicode)]
        public unsafe static extern NTSTATUS BCryptSetProperty(
            IntPtr hObject,
            string pszProperty,
            byte* pbInput,
            int cbInput,
            int dwFlags = 0
        );

        [DllImport(BCryptLib, CharSet = CharSet.Unicode)]
        public static extern NTSTATUS BCryptGenerateKeyPair(
            IntPtr hAlgorithm,
            ref IntPtr hKey,
            int dwLength,
            int dwFlags = 0
        );

        [DllImport(BCryptLib, CharSet = CharSet.Unicode)]
        public static extern NTSTATUS BCryptFinalizeKeyPair(
            IntPtr hKey,
            int dwFlags = 0
        );

        [DllImport(BCryptLib, CharSet = CharSet.Unicode)]
        public unsafe static extern NTSTATUS BCryptExportKey(
          IntPtr hKey,
          IntPtr hExportKey,
          string pszBlobType,
          byte* pbOutput,
          int cbOutput,
          out int pcbResult,
          int dwFlags = 0
        );

        [DllImport(BCryptLib, CharSet = CharSet.Unicode)]
        public unsafe static extern NTSTATUS BCryptImportKeyPair(
           IntPtr hAlgorithm,
           IntPtr hImportKey,
           string pszBlobType,
           ref IntPtr phKey,
           byte* pbInput,
           int cbInput,
           int dwFlags = 0
        );

        [DllImport(BCryptLib, CharSet = CharSet.Unicode)]
        public unsafe static extern NTSTATUS BCryptDeriveKey(
            IntPtr hSharedSecret,
            string pwszKDF,
            BCryptBufferDesc* pParameterList,
            byte* pbDerivedKey,
            int cbDerivedKey,
            ref int pcbResult,
            int dwFlags = 0
        );

        [DllImport(BCryptLib, CharSet = CharSet.Unicode)]
        public static extern NTSTATUS BCryptDestroyKey(
           IntPtr hKey
        );

        [DllImport(BCryptLib, CharSet = CharSet.Unicode)]
        public static extern NTSTATUS BCryptSecretAgreement(
            IntPtr hPrivKey,
            IntPtr hPubKey,
            ref IntPtr phAgreedSecret,
            int dwFlags = 0
        );

        [DllImport(BCryptLib, CharSet = CharSet.Unicode)]
        public static extern NTSTATUS BCryptDestroySecret(
            IntPtr hSecret
        );
    }
}
