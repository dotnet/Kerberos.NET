using System.ComponentModel;

namespace Kerberos.NET.Crypto.Pal.Windows
{
    internal static partial class Interop
    {
        public static void CheckSuccess(this NTSTATUS status)
        {
            if (status != NTSTATUS.STATUS_SUCCESS)
            {
                throw new Win32Exception((int)status);
            }
        }
    }
}
