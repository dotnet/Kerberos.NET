using System.ComponentModel;

namespace Kerberos.NET.Configuration
{
    public class Krb5Logging
    {
        [DisplayName("kdc")]
        public string Kdc { get; set; }

        [DisplayName("admin_server")]
        public string AdminServer { get; set; }

        [DisplayName("default")]
        public string Default { get; set; }
    }
}
