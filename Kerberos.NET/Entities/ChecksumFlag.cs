using System;

namespace Kerberos.NET.Entities
{
    [Flags]
    public enum ChecksumFlag
    {
        GSS_C_DELEG_FLAG = 1 << 0,
        GSS_C_MUTUAL_FLAG = 1 << 1,
        GSS_C_REPLAY_FLAG = 1 << 2,
        GSS_C_SEQUENCE_FLAG = 1 << 3,
        GSS_C_CONF_FLAG = 1 << 4,
        GSS_C_INTEG_FLAG = 1 << 5,
        GSS_C_ANON_FLAG = 1 << 6,
        GSS_C_PROT_READY_FLAG = 1 << 7,
        GSS_C_TRANS_FLAG = 1 << 8,

        GSS_C_DCE_STYLE = 0x1000,
        GSS_C_IDENTIFY_FLAG = 0x2000,
        GSS_C_EXTENDED_ERROR_FLAG = 0x4000,
        GSS_C_AF_NETBIOS = 0x14
    }
}
