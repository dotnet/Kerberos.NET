using System;

namespace Kerberos.NET.Win32
{
    [Flags]
    public enum ExtendedErrorFlag
    {
        EXT_ERROR_CLIENT_INFO = 1,
        EXT_ERROR_CODING_ASN = 2
    }
}
