namespace Kerberos.NET.Crypto.Pal.Windows
{
    internal sealed class Win32CspSha256 : Win32CspHash
    {
        public Win32CspSha256() : base(Interop.CngAlgorithms.SHA256, HashSizes.SHA256) { }
    }
}
