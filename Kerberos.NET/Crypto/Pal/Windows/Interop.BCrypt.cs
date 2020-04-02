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
    }
}
