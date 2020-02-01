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

        public override OSPlatform OSPlatform => OSPlatform.OSX;
    }
}
