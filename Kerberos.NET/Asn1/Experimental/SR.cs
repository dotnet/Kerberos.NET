using Kerberos.NET.Asn1.Experimental;
using System.Linq;

namespace System.Security.Cryptography.Asn1
{
    internal static class SR
    {
        public static string Resource(string name, params object[] args)
        {
            var resource = AsnResources.ResourceManager.GetString(name);

            if (string.IsNullOrWhiteSpace(resource))
            {
                resource = name;
            }

            if (resource.IndexOf("{0}") < 0 && args.Length > 0)
            {
                resource += " " + string.Join(", ", Enumerable.Range(0, args.Length).Select(i => $"{{{i}}}"));
            }

            return string.Format(resource, args);
        }
    }
}
