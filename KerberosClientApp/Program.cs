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
        static async Task Main(string[] args)
        {
            string user = ReadString("UserName", "administrator@corp.identityintervention.com", args);
            string password = ReadString("Password", "P@ssw0rd!", args);
            string s4u = ReadString("S4U", null, args);
            string spn = ReadString("SPN", "host/downlevel.corp.identityintervention.com", args);
            string overrideKdc = ReadString("KDC", "10.0.0.21:88", args);

            await RequestTicketsAsync(user, password, overrideKdc, s4u, spn);

            Write("Press [Any] key to exit...");

            ReadKey();
        }

        private static async Task RequestTicketsAsync(string user, string password, string overrideKdc, string s4u, string spn)
        {
            while (true)
            {
                try
                {
                    await RequestTickets(user, password, overrideKdc, s4u, spn);
                }
                catch (Exception ex)
                {
                    WriteLine(ex);
                    break;
                }
            }
        }

        private static async Task RequestTickets(string user, string password, string overrideKdc, string s4u, string spn)
        {
            var kerbCred = new KerberosPasswordCredential(user, password);

            using KerberosClient client = new KerberosClient(overrideKdc);

            await client.Authenticate(kerbCred);

            spn ??= "host/appservice.corp.identityintervention.com";

            KrbTicket s4uTicket = null;

            if (!string.IsNullOrWhiteSpace(s4u))
            {
                var s4uSelf = await client.GetServiceTicket(
                    kerbCred.UserName,
                    ApOptions.MutualRequired,
                    s4u: s4u
                );

                s4uTicket = s4uSelf.Ticket;
            }

            var ticket = await client.GetServiceTicket(
                spn,
                ApOptions.MutualRequired,
                s4uTicket: s4uTicket
            );

            var encoded = ticket.EncodeApplication().ToArray();

            var authenticator = new KerberosAuthenticator(
                new KeyTable(
                    new KerberosKey(
                        "P@ssw0rd!",
                        principalName: new PrincipalName(
                            PrincipalNameType.NT_PRINCIPAL,
                            "CORP.IDENTITYINTERVENTION.com",
                            new[] { spn }
                        ),
                        saltType: SaltType.ActiveDirectoryUser
                    )
                )
            );

            var validated = (KerberosIdentity)await authenticator.Authenticate(encoded);

            DumpClaims(validated);
        }

        private static void DumpClaims(KerberosIdentity validated)
        {
            WriteLine();

            WriteLine($"UserName: {validated.Name}");
            WriteLine($"AuthType: {validated.AuthenticationType}");
            WriteLine($"Validated by: {validated.ValidationMode}");

            foreach (var kv in validated.Restrictions)
            {
                WriteLine($"Restriction: {kv.Key}");

                foreach (var restriction in kv.Value)
                {
                    WriteLine($"Type: {restriction.Type}");
                    WriteLine($"Value: {restriction}");

                    if (restriction is PrivilegedAttributeCertificate pac)
                    {
                        WriteLine($"{pac.DelegationInformation}");
                    }
                }

                WriteLine();
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
