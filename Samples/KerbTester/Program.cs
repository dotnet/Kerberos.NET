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
