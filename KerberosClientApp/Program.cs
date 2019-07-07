using Kerberos.NET;
using Kerberos.NET.Client;
using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using System.Threading.Tasks;
using static System.Console;

namespace KerberosClientApp
{
    class Program
    {
        static void Main(string[] args)
        {
            MainAsync().Wait();
        }

        private static async Task MainAsync()
        {
            string user = ReadString("UserName", "administrator@corp.identityintervention.com");
            string password = ReadString("Password", "P@ssw0rd!");

            var kerbCred = new KerberosPasswordCredential(user, password);

            KerberosClient client = new KerberosClient();

            var result = await client.Authenticate(kerbCred);

            var ticket = await client.GetServiceTicket("host/appservice.corp.identityintervention.com");

            var encoded = ticket.EncodeAsApplication().ToArray();

            var authenticator = new KerberosAuthenticator(new KeyTable(new KerberosKey("P@ssw0rd!")));

            var validated = (KerberosIdentity)await authenticator.Authenticate(encoded);

            DumpClaims(validated);

            Write("Press [Enter] to exit...");

            ReadKey();
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

        private static string ReadString(string label, string defaultVal = null)
        {
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
