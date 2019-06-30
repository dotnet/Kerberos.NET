using System.Linq;

namespace System.Security.Cryptography.Asn1
{
    internal static class SR
    {
        public static string Resource(string name, params object[] args)
        {

            var parms = string.Join(", ", Enumerable.Range(0, args.Length).Select(i => $"{{{i}}}"));

            return name + " " + string.Format(parms, args);
        }
    }
}
