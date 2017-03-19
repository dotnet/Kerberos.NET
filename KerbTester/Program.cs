using Syfuhs.Security.Kerberos;
using System;
using System.Linq;

namespace KerbTester
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length < 2)
            {
                ShowHelp();
                return;
            }

            var validator = new SimpleKerberosValidator(args[0])
            {
                Logger = W
            };

            if (args.Contains("novalidate"))
            {
                validator.ValidateAfterDecrypt = false;
            }

            try
            {
                var identity = validator.Validate(args[1]);

                if (identity == null)
                {
                    W("Identity could not be decrypted");

                    return;
                }

                foreach (var c in identity.Claims)
                {
                    W($"{c.Value}: {c.Type}");
                }
            }
            catch (Exception ex)
            {
                W(ex.Message);
            }
        }

        private static void W(string w)
        {
            Console.WriteLine(w);
            Console.WriteLine();
        }

        private static void ShowHelp()
        {
            W("");
            W(" Usage: KerbTester.exe <key> <request> [novalidate]");
            W("");
            W(" ================================================");
            W("");
            W("    key          The key (password) of the SPN this request is targeting");
            W("    request      The kerberos request in a base64 encoding");
            W("    novalidate   Do not validate token");
            W("");
        }
    }
}
