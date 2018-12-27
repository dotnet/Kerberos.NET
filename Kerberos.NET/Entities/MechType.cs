using System.Diagnostics;
using System.Security.Cryptography;

namespace Kerberos.NET.Entities
{
    [DebuggerDisplay("{Mechanism} {Oid}")]
    [TreatAsTag(UniversalTag, "ObjectIdentifier")]
    public sealed class MechType
    {
        public const string SPNEGO = "1.3.6.1.5.5.2";
        public const string KerberosV5Legacy = "1.2.840.48018.1.2.2";
        public const string KerberosV5 = "1.2.840.113554.1.2.2";
        public const string NTLM = "1.3.6.1.4.1.311.2.2.10";
        public const string NEGOEX = "1.3.6.1.4.1.311.2.2.30";

        public const int UniversalTag = 6;

        public string Mechanism { get; }

        public string Oid { get; }

        private Oid oid;

        [KerberosIgnore]
        public Oid ObjectIdentifier { get { return oid ?? (oid = new Oid(Oid)); } }

        public MechType(string oid)
        {
            Oid = oid;
            Mechanism = LookupOid(oid);
        }

        private static string LookupOid(string oid)
        {
            switch (oid)
            {
                case SPNEGO:
                    return "SPNEGO";

                case KerberosV5Legacy:
                    return "Kerberos V5 Legacy";

                case KerberosV5:
                    return "Kerberos V5";

                case NTLM:
                    return "NTLM";

                case NEGOEX:
                    return "NegoEx";
            }

            return "";
        }
    }
}
