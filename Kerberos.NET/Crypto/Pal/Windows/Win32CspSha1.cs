namespace Kerberos.NET.Crypto.Pal.Windows
{
    internal sealed class Win32CspSha1 : Win32CspHash
    {
        public Win32CspSha1() : base(Interop.CngAlgorithms.SHA1, HashSizes.SHA1) { }
    }
}
