﻿using System.Diagnostics;

namespace Kerberos.NET.Entities
{
    [DebuggerDisplay("{Mechanism} {Oid}")]
    public static class MechType
    {
        public const string SPNEGO = "1.3.6.1.5.5.2";
        public const string KerberosV5Legacy = "1.2.840.48018.1.2.2";
        public const string KerberosV5 = "1.2.840.113554.1.2.2";
        public const string KerberosUser2User = "1.2.840.113554.1.2.2.3";
        public const string NTLM = "1.3.6.1.4.1.311.2.2.10";
        public const string NEGOEX = "1.3.6.1.4.1.311.2.2.30";

        public static string LookupOid(string oid)
        {
            switch (oid)
            {
                case SPNEGO:
                    return "SPNEGO";

                case KerberosV5Legacy:
                    return "Kerberos V5 Legacy";

                case KerberosV5:
                    return "Kerberos V5";

                case KerberosUser2User:
                    return "Kerberos User2User";

                case NTLM:
                    return "NTLM";

                case NEGOEX:
                    return "NegoEx";
            }

            return "";
        }
    }
}
