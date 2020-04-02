using System;
using System.Runtime.InteropServices;

namespace Kerberos.NET.Crypto.Pal.Windows
{
    internal static partial class Interop
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct BCRYPT_DH_PARAMETER
        {
            public BCRYPT_DH_PARAMETER_HEADER header;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct BCRYPT_DH_PARAMETER_HEADER
        {
            public int cbLength;
            public int dwMagic;
            public int cbKeyLength;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct BCRYPT_DH_KEY_BLOB
        {
            public BCRYPT_DH_KEY_BLOB_HEADER header;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct BCRYPT_DH_KEY_BLOB_HEADER
        {
            public int dwMagic;
            public int cbKey;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct BCryptBuffer
        {
            public int cbBuffer;
            public int BufferType;
            public IntPtr pvBuffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct BCryptBufferDesc
        {
            public int ulVersion;
            public int cBuffers;
            public IntPtr pBuffers;
        }
    }
}
