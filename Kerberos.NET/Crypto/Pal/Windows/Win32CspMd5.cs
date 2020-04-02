namespace Kerberos.NET.Crypto.Pal.Windows
{
#if WEAKCRYPTO
    internal sealed class Win32CspMd5 : Win32CspHash
    {
        private const int CALG_MD5 = 0x00008003;
        private const int MD5HashSize = 16;

        public Win32CspMd5() : base("MD5", CALG_MD5, MD5HashSize) { }
    }
#endif
}
