using Syfuhs.Security.Kerberos;
using Syfuhs.Security.Kerberos.Aes;
using Syfuhs.Security.Kerberos.Crypto;
using System;
using System.IO;
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

                KeyTable keytab;

                if (args[0] == "keytab")
                {
                    keytab = new KeyTable(File.ReadAllBytes("sample.keytab"));
                }
                else
                {
                    keytab = new KeyTable(new KerberosKey(args[0], host: args[1]));
                }

                var validator = new KerberosValidator(keytab)
                {
                    Logger = W
                };

                var authenticator = new KerberosAuthenticator(validator);

                if (args.Contains("novalidate"))
                {
                    validator.ValidateAfterDecrypt = ValidationAction.Replay;
                }

                var identity = authenticator.Authenticate(raw);

                if (identity == null)
                {
                    W("Identity could not be decrypted");

                    return;
                }

                foreach (var c in identity.Claims)
                {
                    W($"{c.Type}: {c.Value}");
                }
            }
            catch (Exception ex)
            {
                W(ex.Message);
            }

            ;
        }

        private static void W(string w)
        {
            Console.WriteLine(w);
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
