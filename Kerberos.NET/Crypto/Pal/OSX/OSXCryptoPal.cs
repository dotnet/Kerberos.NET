using System.Runtime.InteropServices;

namespace Kerberos.NET.Crypto
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
