// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System.Diagnostics;

namespace Kerberos.NET.Entities
{
    [DebuggerDisplay("{Mechanism} {Oid}")]
    public static class MechType
    {
        public const string SPNEGO = "1.3.6.1.5.5.2";
        public const string KerberosV5Legacy = "1.2.840.48018.1.2.2";
        public const string KerberosV5 = "1.3.6.1.5.2";
        public const string KerberosGssApi = "1.2.840.113554.1.2.2";
        public const string KerberosUser2User = "1.2.840.113554.1.2.2.3";
        public const string NTLM = "1.3.6.1.4.1.311.2.2.10";
        public const string NEGOEX = "1.3.6.1.4.1.311.2.2.30";
        public const string IAKerb = "1.3.6.1.5.2.5";

        public static string LookupOid(string oid)
        {
            return oid switch
            {
                SPNEGO => "SPNEGO",
                KerberosV5Legacy => "Kerberos V5 Legacy",
                KerberosV5 => "Kerberos V5",
                KerberosGssApi => "Kerberos GSS API",
                KerberosUser2User => "Kerberos User2User",
                NTLM => "NTLM",
                NEGOEX => "NegoEx",
                IAKerb => "IAKerb",
                _ => string.Empty,
            }; ;
        }
    }
}
