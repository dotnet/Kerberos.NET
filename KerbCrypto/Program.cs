using Syfuhs.Security.Kerberos;
using Syfuhs.Security.Kerberos.Aes;
using System;
using System.Collections.Generic;
using System.IO;

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
            AESKerberosConfiguration.Register();

            foreach (var f in Files)
            {
                var data = File.ReadAllBytes("data\\" + f.Key);
                var key = File.ReadAllBytes("data\\" + f.Value);

                W($"Decrypting {f.Key} with key {f.Value}", ConsoleColor.Green);

                var validator = new SimpleKerberosValidator(key)
                {
                    Logger = W,
                    ValidateAfterDecrypt = false
                };

                var result = validator.Validate(data);

                ;

                if (result == null)
                {
                    throw new InvalidDataException("Could not decrypt token");
                }
            }
        }

        private static void W(string w, ConsoleColor color) {
            Console.ForegroundColor = color;

            W(w);

            Console.ResetColor();
        }

        private static void W(string w)
        {
            Console.WriteLine(w);
            Console.WriteLine();
        }
    }
}
