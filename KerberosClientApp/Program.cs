using Kerberos.NET;
using Kerberos.NET.Client;
using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Transport;
using Microsoft.Win32;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using static System.Console;

namespace KerberosClientApp
{
    class Program
    {
        static async Task Main(string[] args)
        {
            var cert = SelectCertificate(args);

            string user = ReadString("UserName", "administrator@corp.identityintervention.com", args);
            string password = ReadString("Password", "P@ssw0rd!", args, ReadMasked);
            string s4u = ReadString("S4U", null, args);
            string spn = ReadString("SPN", "host/downlevel.corp.identityintervention.com", args);
            string overrideKdc = ReadString("KDC", "10.0.0.21:88", args);

            bool randomDH = false;

            if (cert != null)
            {
                randomDH = ReadString("RandomDH", "n", args).Equals("y", StringComparison.InvariantCultureIgnoreCase);
            }

            await RequestTicketsAsync(cert, user, password, overrideKdc, s4u, spn, randomDH);

            Write("Press [Any] key to exit...");

            ReadKey();
        }

        private static X509Certificate2 SelectCertificate(string[] args)
        {
            string thumbprint = "";

            if (args.Length % 2 == 0)
            {
                for (var i = 0; i < args.Length; i += 2)
                {
                    if (args[i] == "-thumbprint")
                    {
                        thumbprint = args[i + 1];
                    }
                }
            }

            var readCert = ReadString("Certificate", "N", args).ToLowerInvariant() == "y";

            if (!readCert)
            {
                return null;
            }

            using (var store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                store.Open(OpenFlags.ReadOnly);

                var clientCerts = store.Certificates.Find(X509FindType.FindByApplicationPolicy, "1.3.6.1.5.5.7.3.2", false);

                if (!string.IsNullOrWhiteSpace(thumbprint))
                {
                    clientCerts = clientCerts.Find(X509FindType.FindByThumbprint, thumbprint, false);
                }

                var hwnd = Process.GetCurrentProcess().MainWindowHandle;

                var certs = X509Certificate2UI.SelectFromCollection(clientCerts, "Client Certificate", "Select Client Certificate for PKInit", X509SelectionFlag.SingleSelection, hwnd);

                foreach (var cert in certs)
                {
                    if (cert.HasPrivateKey)
                    {
                        return cert;
                    }
                }

                return null;
            }
        }

        private static async Task RequestTicketsAsync(
            X509Certificate2 cert,
            string user,
            string password,
            string overrideKdc,
            string s4u,
            string spn,
            bool randomDH
        )
        {
            while (true)
            {
                try
                {
                    await RequestTickets(cert, user, password, overrideKdc, s4u, spn, randomDH);
                }
                catch (Exception ex)
                {
                    WriteLine(ex);
                    break;
                }
            }
        }

        private class RandomDHAsymmetricCredential : KerberosAsymmetricCredential
        {
            public RandomDHAsymmetricCredential(X509Certificate2 cert, string username = null)
                : base(cert, username)
            {
            }

            protected override void VerifyKdcSignature(SignedCms signed)
            {
                signed.CheckSignature(verifySignatureOnly: true);
            }

            protected override bool CacheKeyAgreementParameters(IKeyAgreement agreement)
            {
                return false;
            }

            private static readonly Random random = new Random();

            protected override IKeyAgreement StartKeyAgreement()
            {
                IKeyAgreement agreement = null;

                switch (random.Next(4))
                {
                    case 0:
                        agreement = new BCryptDiffieHellmanOakleyGroup14();
                        break;
                    case 1:
                        agreement = new BCryptDiffieHellmanOakleyGroup2();
                        break;
                    case 2:
                        agreement = new ManagedDiffieHellmanOakley14();
                        break;
                    case 3:
                        agreement = new ManagedDiffieHellmanOakley2();
                        break;
                }

                WriteLine($"DH Type: {agreement.GetType()}");

                if (agreement == null)
                {
                    throw new ArgumentException("How did it get here?");
                }

                return agreement;
            }
        }

        private class TrustedKdcAsymmetricCredential : KerberosAsymmetricCredential
        {
            public TrustedKdcAsymmetricCredential(X509Certificate2 cert, string username = null)
                : base(cert, username)
            {
            }

            protected override void VerifyKdcSignature(SignedCms signed)
            {
                signed.CheckSignature(verifySignatureOnly: true);
            }

            protected override IKeyAgreement StartKeyAgreement()
            {
                var privateKey = ReadCachedDH(UserName);

                if (privateKey != null)
                {
                    return CryptoPal.Platform.DiffieHellmanModp14(privateKey);
                }

                return CryptoPal.Platform.DiffieHellmanModp14();
            }

            private DiffieHellmanKey ReadCachedDH(string userName)
            {
                using (var reg = Registry.CurrentUser.CreateSubKey($"SOFTWARE\\Kerberos.NET\\{userName}"))
                {
                    var val = (string)reg.GetValue("DHParameter");

                    if (!string.IsNullOrWhiteSpace(val))
                    {
                        return ConvertKey(JsonConvert.DeserializeObject<Dictionary<string, object>>(val));
                    }
                }

                return null;
            }

            private DiffieHellmanKey ConvertKey(Dictionary<string, object> dictionary)
            {
                var key = new DiffieHellmanKey
                {
                    KeyLength = (int)(long)dictionary["KeyLength"],
                    Type = (AsymmetricKeyType)((long)dictionary["Type"]),
                    Modulus = Convert.FromBase64String(dictionary["Modulus"].ToString()),
                    Generator = Convert.FromBase64String(dictionary["Generator"].ToString()),
                    Public = Convert.FromBase64String(dictionary["PublicKey"].ToString()),
                    Factor = Convert.FromBase64String(dictionary["Factor"].ToString()),
                    Private = Convert.FromBase64String(dictionary["PrivateKey"].ToString())
                };

                return key;
            }

            private static Dictionary<string, object> ConvertKey(DiffieHellmanKey key)
            {
                return new Dictionary<string, object> {
                    { "KeyLength", key.KeyLength },
                    { "Type", key.Type },
                    { "Modulus", key.Modulus.ToArray() },
                    { "Generator", key.Generator.ToArray() },
                    { "PublicKey", key.Public.ToArray() },
                    { "Factor", key.Factor.ToArray() },
                    { "PrivateKey", key.Private.ToArray() }
                };
            }

            protected override bool CacheKeyAgreementParameters(IKeyAgreement agreement)
            {
                var serializedPk = JsonConvert.SerializeObject(ConvertKey(agreement.PrivateKey));

                using (var reg = Registry.CurrentUser.CreateSubKey($"SOFTWARE\\Kerberos.NET\\{UserName}"))
                {
                    reg.SetValue("DHParameter", serializedPk, RegistryValueKind.String);
                }

                return true;
            }
        }

        private static async Task RequestTickets(
            X509Certificate2 cert,
            string user,
            string password,
            string overrideKdc,
            string s4u,
            string spn, bool retryDH)
        {
            KerberosCredential kerbCred;

            if (cert == null)
            {
                kerbCred = new KerberosPasswordCredential(user, password);
            }
            else
            {
                var chain = new X509Chain();
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                chain.Build(cert);

                var kdcCerts = new List<X509Certificate2>();

                for (var i = 0; i < chain.ChainElements.Count; i++)
                {
                    var c = chain.ChainElements[i].Certificate;

                    if (c.Thumbprint != cert.Thumbprint)
                    {
                        kdcCerts.Add(c);
                    }
                }

                if (retryDH)
                {
                    kerbCred = new RandomDHAsymmetricCredential(cert, user);
                }
                else
                {
                    kerbCred = new TrustedKdcAsymmetricCredential(cert, user);
                }
            }

            KerberosClient client;

            if (Uri.TryCreate(overrideKdc, UriKind.Absolute, out Uri kdcProxy))
            {
                var kdcProxyTransport = new HttpsKerberosTransport()
                {
                    DomainPaths = new Dictionary<string, Uri>
                    {
                        { kdcProxy.DnsSafeHost, kdcProxy },
                        { kerbCred.Domain, kdcProxy }
                    }
                };

                client = new KerberosClient(null, kdcProxyTransport);
            }
            else
            {
                client = new KerberosClient(overrideKdc);
            }

            using (client)
            using (kerbCred as IDisposable)
            {
                await client.Authenticate(kerbCred);

                ForegroundColor = ConsoleColor.Green;

                spn = spn ?? "host/appservice.corp.identityintervention.com";

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

                DumpTicket(ticket);

                ResetColor();

                if (!retryDH)
                {
                    try
                    {
                        await TryValidate(spn, ticket);
                    }
                    catch (Exception ex)
                    {
                        ForegroundColor = ConsoleColor.Yellow;

                        WriteLine(ex.Message);

                        ResetColor();
                        //WriteLine(ex.StackTrace);
                    }
                }
            }
        }

        private static async Task TryValidate(string spn, KrbApReq ticket)
        {
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

        private static void DumpTicket(KrbApReq ticket)
        {
            WriteLine();

            WriteLine($"Type: {ticket.MessageType}");
            WriteLine($"APOptions: {ticket.ApOptions}");
            WriteLine($"Realm: {ticket.Ticket.Realm}");
            WriteLine($"SName: {ticket.Ticket.SName.FullyQualifiedName}");

            WriteLine();
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

        private static string ReadString(string label, string defaultVal = null, string[] args = null, Func<string> reader = null)
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

            reader ??= ReadLine;

            var val = reader();

            if (string.IsNullOrWhiteSpace(val))
            {
                val = defaultVal;
            }

            return val;
        }

        private static string ReadMasked()
        {
            var masked = "";

            do
            {
                ConsoleKeyInfo key = ReadKey(true);

                if (key.Key != ConsoleKey.Backspace &&
                    key.Key != ConsoleKey.Enter &&
                    !char.IsControl(key.KeyChar))
                {
                    masked += key.KeyChar;

                    Write("*");
                }
                else if (key.Key == ConsoleKey.Backspace && masked.Length > 0)
                {
                    Write("\b \b");
                    masked = masked[0..^1];
                }
                else if (key.Key == ConsoleKey.Enter)
                {
                    WriteLine();
                    break;
                }
            }
            while (true);

            return masked;
        }
    }
}
