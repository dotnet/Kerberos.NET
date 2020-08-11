using System;

namespace Kerberos.NET.Crypto.Pal.Windows
{
    internal static partial class Interop
    {
        public static class CngAlgorithms
        {
            // https://docs.microsoft.com/en-us/windows/win32/seccng/cng-algorithm-identifiers

            public const string AES = "AES";            // BCRYPT_AES_ALGORITHM
            public const string DH = "DH";              // BCRYPT_DH_ALGORITHM
            public const string MD4 = "MD4";            // BCRYPT_MD4_ALGORITHM   
            public const string MD5 = "MD5";            // BCRYPT_MD5_ALGORITHM   
            public const string SHA1 = "SHA1";          // BCRYPT_SHA1_ALGORITHM  
            public const string SHA256 = "SHA256";      // BCRYPT_SHA256_ALGORITHM
        }

        public enum NTSTATUS : uint
        {
            // https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55

            STATUS_SUCCESS = 0x00000000,
            STATUS_INVALID_HANDLE = 0xC0000008,
            STATUS_INVALID_PARAMETER = 0xC000000D,
            STATUS_NO_MEMORY = 0xC0000017,
            STATUS_BUFFER_TOO_SMALL = 0xC0000023,
            STATUS_NOT_SUPPORTED = 0xC00000BB,
            STATUS_NOT_FOUND = 0xC0000225
        }

        [Flags]
        public enum BCryptOpenAlgorithmProviderFlags : int
        {
            None = 0x0,
            BCRYPT_ALG_HANDLE_HMAC_FLAG = 0x8,
            BCRYPT_HASH_REUSABLE_FLAG = 0x20
        }

        [Flags]
        public enum BCryptCreateHashFlags : int
        {
            None = 0x00000000,
            BCRYPT_HASH_REUSABLE_FLAG = 0x00000020,
        }
    }
}
