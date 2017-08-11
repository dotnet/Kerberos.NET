using Kerberos.NET;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace KerbCrypto
{
    class Program
    {
        // test files sourced from https://github.com/drankye/haox
        // original Apache 2.0 license

        private static readonly Dictionary<string, string> Files = new Dictionary<string, string> {
            { "rc4-kerberos-data", "rc4-key-data" },
            { "rc4-spnego-data", "rc4-key-data" },
            { "aes128-kerberos-data", "aes128-key-data" },
            { "aes128-spnego-data", "aes128-key-data" },
            { "aes256-kerberos-data", "aes256-key-data" },
            { "aes256-spnego-data", "aes256-key-data" }
        };

        static void Main(string[] args)
        {
            MainAsync().Wait();
        }

        private static async System.Threading.Tasks.Task MainAsync()
        {
            foreach (var f in Files)
            {
                var data = File.ReadAllBytes("data\\" + f.Key);
                var key = File.ReadAllBytes("data\\" + f.Value);

                W($"Decrypting {f.Key} with key {f.Value}", ConsoleColor.Green);

                var validator = new KerberosValidator(key)
                {
                    Logger = W,
                    ValidateAfterDecrypt = ValidationAction.Replay
                };

                var authenticator = new KerberosAuthenticator(validator);

                var result = await authenticator.Authenticate(data);

                ;

                if (result == null)
                {
                    throw new InvalidDataException("Could not decrypt token");
                }

                foreach (var c in result.Claims.OrderBy(c => c.Type))
                {
                    W($"{c.Type}: {c.Value}");
                }

                W("");

                ;
            }

            ;
        }

        private static void W(string w, ConsoleColor color)
        {
            Console.ForegroundColor = color;

            W(w);

            Console.ResetColor();
        }

        private static void W(string w)
        {
            Console.WriteLine(w);
        }
    }
}
