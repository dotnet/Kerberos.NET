using System;
using RtIs = System.Runtime.InteropServices;

namespace Kerberos.NET
{
    public static class OSPlatform
    {
        public static readonly bool IsWindows = RtIs.RuntimeInformation.IsOSPlatform(RtIs.OSPlatform.Windows);

        public static readonly bool IsLinux = RtIs.RuntimeInformation.IsOSPlatform(RtIs.OSPlatform.Linux);

        public static readonly bool IsOsX = RtIs.RuntimeInformation.IsOSPlatform(RtIs.OSPlatform.OSX);
    }
}
