namespace Kerberos.NET.Crypto.Pal.Windows
{
#if WEAKCRYPTO
    internal sealed class Win32CspMd4 : Win32CspHash
    {
        public Win32CspMd4() : base("MD4", (int)Interop.Algorithms.CALG_MD4, HashSizes.MD4) { }
    }
#endif
}
