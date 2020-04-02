using System;

namespace Kerberos.NET.Crypto.Pal.Windows
{
    internal static partial class Interop
    {
        public enum ProviderType : int
        {
            PROV_RSA_FULL = 1,
            PROV_DSS_DH = 13,
            PROV_RSA_AES = 24
        }

        public enum Algorithms : int
        {
            CALG_MD4 = 0x00008002,
            CALG_MD5 = 0x00008003,
            CALG_SHA1 = 0x00008004,
            CALG_SHA_256 = 0x0000800c
        }

        [Flags]
        public enum CryptAcquireContextFlags : uint
        {
            None = 0x00000000,
            CRYPT_NEWKEYSET = 0x00000008,         // CRYPT_NEWKEYSET
            CRYPT_DELETEKEYSET = 0x00000010,      // CRYPT_DELETEKEYSET
            CRYPT_MACHINE_KEYSET = 0x00000020,    // CRYPT_MACHINE_KEYSET
            CRYPT_SILENT = 0x00000040,            // CRYPT_SILENT
            CRYPT_VERIFYCONTEXT = 0xF0000000      // CRYPT_VERIFYCONTEXT
        }
    }
}
