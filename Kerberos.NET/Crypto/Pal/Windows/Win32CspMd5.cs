namespace Kerberos.NET.Crypto.Pal.Windows
{
#if WEAKCRYPTO
    internal sealed class Win32CspMd5 : Win32CspHash
    {
        public Win32CspMd5() : base(Interop.CngAlgorithms.MD5, HashSizes.MD5) { }
    }
#endif
}
