using System;

namespace Kerberos.NET
{
    internal static class OSPlatform
    {
        public static readonly bool IsWindows = (Environment.OSVersion.Platform == PlatformID.Win32S)
            || (Environment.OSVersion.Platform == PlatformID.Win32Windows)
            || (Environment.OSVersion.Platform == PlatformID.Win32NT)
            || (Environment.OSVersion.Platform == PlatformID.WinCE);

        public static readonly bool IsLinux = (Environment.OSVersion.Platform == PlatformID.Unix);

        public static readonly bool IsOsX = (Environment.OSVersion.Platform == PlatformID.MacOSX);
    }
}
