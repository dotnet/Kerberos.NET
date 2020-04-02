namespace Kerberos.NET.Crypto.Pal
{
    internal class OSXCryptoPal : LinuxCryptoPal
    {
        public OSXCryptoPal()
        {
            if (!IsOsX)
            {
                throw PlatformNotSupported();
            }
        }
    }
}
