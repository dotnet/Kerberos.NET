using Syfuhs.Security.Kerberos;
using Syfuhs.Security.Kerberos.Aes;
using Syfuhs.Security.Kerberos.Crypto;
using System;
using System.Linq;
using System.Text;

namespace KerbTester
{
    class Program
    {
        static void Main(string[] args)
        {
            AESKerberosConfiguration.Register();

            if (args.Length < 3)
            {
                ShowHelp();
                return;
            }

            try
            {
                string raw = "";

                switch (args[2])
                {
                    case "aes":
                    case "aes256":
                        raw = "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";
                        break;
                    case "aes128":
                        raw = "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";
                        break;
                    case "rc4":
                        raw = "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";
                        break;
                    case "spnego":
                        raw = "YIGeBgYrBgEFBQKggZMwgZCgGjAYBgorBgEEAYI3AgIeBgorBgEEAYI3AgIKonIEcE5FR09FWFRTAAAAAAAAAABgAAAAcAAAAAPx046cicVOngxMfxUsCsEIMeUM39SSXP1N9DuDVIU3IFosQ3eWTsKOPdfTNWD4SAAAAAAAAAAAYAAAAAEAAAAAAAAAAAAAAMNbiTClcBVAolAmCpGQrZA=";
                        break;
                    default:
                        raw = args[1];
                        break;
                }

                var validator = new SimpleKerberosValidator(new KerberosKey(args[0], host: args[1]))
                {
                    Logger = W
                };

                if (args.Contains("novalidate"))
                {
                    validator.ValidateAfterDecrypt = false;
                }

                var identity = validator.Validate(raw);

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
            W(" Usage:   KerbTester.exe <key> <host> [aes|aes256|rc4] [request] [novalidate]");
            W("");
            W(" Example: KerbTester.exe P@ssw0rd! server01 YIIHCAYGKw... novalidate");
            W("");
            W(" ================================================");
            W("");
            W("    key          The key (password) of the SPN this request is targeting");
            W("    host         The samAccountName of the SPN this request is targeting (used for salt generation)");
            W("    aes          Process a sample AES 256 encrypted token");
            W("    aes128       Process a sample AES 128 encrypted token");
            W("    rc4          Process a sample RC4 encrypted token");
            W("    request      Process kerberos request in a base64 encoding");
            W("    novalidate   Do not validate token");
            W("");
        }

        private static byte[] MD4(byte[] key)
        {
            return new MD4().ComputeHash(key);
        }

        private static byte[] MD4(string password)
        {
            return MD4(Encoding.Unicode.GetBytes(password));
        }
    }
}
