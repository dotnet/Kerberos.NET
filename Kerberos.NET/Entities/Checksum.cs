using Kerberos.NET.Asn1;
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

        GSS_C_DCE_STYLE = 1 << 13,
        GSS_C_IDENTIFY_FLAG = 1 << 14,
        GSS_C_EXTENDED_ERROR_FLAG = 1 << 15

        // GSS_C_AF_NETBIOS = 0x14 -- not really a flag
    }

    public class Checksum
    {
        private const int ChecksumContainsDelegationType = 0x8003;

        public Checksum Decode(Asn1Element element)
        {
            for (var i = 0; i < element.Count; i++)
            {
                var node = element[i];

                switch (node.ContextSpecificTag)
                {
                    case 0:
                        ChecksumType = node[0].AsInt();
                        break;
                    case 1:
                        if (ChecksumType == ChecksumContainsDelegationType)
                        {
                            Delegation = new DelegationInfo().Decode(node[0].Value);
                        }
                        break;
                }
            }

            return this;
        }

        public int ChecksumType;

        public DelegationInfo Delegation;
    }
}
