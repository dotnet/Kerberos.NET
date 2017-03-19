namespace Syfuhs.Security.Kerberos.Entities
{
    public class MechType
    {
        public const int ContextTag = 6;

        public string Mechanism { get; private set; }

        public string Oid { get; private set; }

        public MechType(string oid)
        {
            Oid = oid;
            Mechanism = LookupOid(oid);
        }

        private static string LookupOid(string oid)
        {
            switch (oid)
            {
                case "1.3.6.1.5.5.2":
                    return "SPNEGO";

                case "1.2.840.48018.1.2.2":
                    return "Kerberos V5 Legacy";

                case "1.2.840.113554.1.2.2":
                    return "Kerberos V5";

                case "1.3.6.1.4.1.311.2.2.10":
                    return "NTLM";
            }

            return "";
        }
    }

}
