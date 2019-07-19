using Kerberos.NET;
using Kerberos.NET.Client;
using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using System;
using System.Threading.Tasks;
using static System.Console;

namespace KerberosClientApp
{
    class Program
    {

        static void Main(string[] args)
        {
            string user = ReadString("UserName", "administrator@corp.identityintervention.com", args);
            string password = ReadString("Password", "P@ssw0rd!", args);
            string overrideKdc = ReadString("KDC", null, args);

            bool overkill = string.Equals(ReadString("async", "false", args), "true", StringComparison.OrdinalIgnoreCase);

            for (var i = 0; i < 10; i++)
            {
                _ = RequestTicketsAsync(user, password, overrideKdc);

                if (!overkill)
                {
                    break;
                }
            }

            Write("Press [Any] key to exit...");

            ReadKey();
        }

        private static async Task RequestTicketsAsync(string user, string password, string overrideKdc)
        {
            while (true)
            {
                try
                {
                    await RequestTickets(user, password, overrideKdc);
                }
                catch (Exception ex)
                {
                    WriteLine(ex.Message);
                }
            }
        }

        private static async Task RequestTickets(string user, string password, string overrideKdc)
        {
            var kerbCred = new KerberosPasswordCredential(user, password);

            KerberosClient client = new KerberosClient(overrideKdc);

            await client.Authenticate(kerbCred);

            var ticket = await client.GetServiceTicket(
                "host/appservice.corp.identityintervention.com",
                ApOptions.MutualRequired
            );

            var encoded = ticket.EncodeAsApplication().ToArray();

            var authenticator = new KerberosAuthenticator(new KeyTable(new KerberosKey("P@ssw0rd!")));

            var validated = (KerberosIdentity)await authenticator.Authenticate(encoded);

            DumpClaims(validated);
        }

        private static void DumpClaims(KerberosIdentity validated)
        {
            WriteLine();

            WriteLine($"UserName: {validated.Name}");
            WriteLine($"AuthType: {validated.AuthenticationType}");
            WriteLine($"Validated by: {validated.ValidationMode}");


            foreach (var restriction in validated.Restrictions)
            {
                WriteLine($"Restriction: {restriction.Key}");
            }

            WriteLine();

            foreach (var claim in validated.Claims)
            {
                WriteLine($"Type: {claim.Type}");
                WriteLine($"Value: {claim.Value}");
                WriteLine();
            }
        }

        private static string ReadString(string label, string defaultVal = null, string[] args = null)
        {
            if (args.Length % 2 == 0)
            {
                for (var i = 0; i < args.Length; i += 2)
                {
                    var argName = args[i].Replace("-", "").Replace("/", "").Replace(":", "");

                    if (string.Equals(argName, label, StringComparison.InvariantCultureIgnoreCase))
                    {
                        defaultVal = args[i + 1];
                    }
                }
            }

            Write($"{label} ({defaultVal}): ");

            var val = ReadLine();

            if (string.IsNullOrWhiteSpace(val))
            {
                val = defaultVal;
            }

            return val;
        }
    }
}
