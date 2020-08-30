using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Kerberos.NET;
using Kerberos.NET.Client;
using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Console;
using Microsoft.Win32;
using Newtonsoft.Json;
using static System.Console;

namespace KerberosClientApp
{
    class Program
    {
        static async Task Main(string[] args)
        {
            bool prompt = ReadString("prompt", "y", args, required: false, reader: () => { W(); return null; }).Equals("y", StringComparison.InvariantCultureIgnoreCase);

            var cert = SelectCertificate(args, prompt);
            string user = ReadString("UserName", "administrator@corp.identityintervention.com", args, prompt: prompt);
            string password = ReadString("Password", "P@ssw0rd!", args, ReadMasked, prompt: prompt);
            string s4u = ReadString("S4U", null, args, required: false, prompt: prompt);
            string spn = ReadString("SPN", "host/downlevel.corp.identityintervention.com", args, prompt: prompt);
            string overrideKdc = ReadString("KDC", "", args, required: false, prompt: prompt);

            bool includeCNameHint = ReadString("Hint", "n", args, required: false, prompt: prompt).Equals("y", StringComparison.InvariantCultureIgnoreCase);

            bool cacheToFile = ReadString("Cache", "n", args, required: false, prompt: prompt).Equals("y", StringComparison.InvariantCultureIgnoreCase);

            string servicePassword = ReadString("ServicePassword", "P@ssw0rd!", args, required: false, prompt: prompt);
            string serviceSalt = ReadString("ServiceSalt", "", args, required: false, prompt: prompt);

            bool randomDH = false;

            if (cert != null)
            {
                randomDH = ReadString("RandomDH", "n", args).Equals("y", StringComparison.InvariantCultureIgnoreCase);
            }

            W();

            await RequestTicketsAsync(cert, user, password, overrideKdc, s4u, spn, randomDH, includeCNameHint, servicePassword, serviceSalt, cacheToFile);

            Write("Press [Any] key to exit...");

            ReadKey();
        }

        private static X509Certificate2 SelectCertificate(string[] args, bool prompt)
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

            var readCert = ReadString("Certificate", "N", args, prompt: prompt).ToLowerInvariant() == "y";

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
            bool randomDH,
            bool includeCNameHint,
            string servicePassword,
            string serviceSalt,
            bool cacheToFile
        )
        {
            if (!cacheToFile && File.Exists("krb5cc"))
            {
                File.Delete("krb5cc");
            }

            while (true)
            {
                try
                {
                    await RequestTickets(cert, user, password, overrideKdc, s4u, spn, randomDH, includeCNameHint, servicePassword, serviceSalt, cacheToFile);
                    //break;
                }
                catch (Exception ex)
                {
                    W(ex.ToString(), ConsoleColor.Red);
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

                W($"DH Type: {agreement.GetType()}");

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
                    PublicComponent = Convert.FromBase64String(dictionary["PublicKey"].ToString()),
                    Factor = Convert.FromBase64String(dictionary["Factor"].ToString()),
                    PrivateComponent = Convert.FromBase64String(dictionary["PrivateKey"].ToString())
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
                    { "PublicKey", key.PublicComponent.ToArray() },
                    { "Factor", key.Factor.ToArray() },
                    { "PrivateKey", key.PrivateComponent.ToArray() }
                };
            }

            protected override bool CacheKeyAgreementParameters(IKeyAgreement agreement)
            {
                var serializedPk = JsonConvert.SerializeObject(ConvertKey(agreement.PrivateKey as DiffieHellmanKey));

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
            string spn,
            bool retryDH,
            bool includeCNameHint,
            string servicePassword,
            string serviceSalt,
            bool cacheToFile
        )
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

            var factory = LoggerFactory.Create(builder =>
            {
                builder.AddConsole(opt => opt.IncludeScopes = true);
                builder.AddFilter<ConsoleLoggerProvider>(level => level >= LogLevel.Trace);
            });

            var client = new KerberosClient(logger: factory);

            if (Uri.TryCreate(overrideKdc, UriKind.Absolute, out Uri kdcProxy))
            {
                client.Configuration.Realms[kdcProxy.DnsSafeHost].Kdc.Add(kdcProxy.OriginalString);
                client.Configuration.Realms[kerbCred.Domain].Kdc.Add(kdcProxy.OriginalString);
                client.Configuration.Defaults.DnsLookupKdc = false;
            }
            else if (!string.IsNullOrWhiteSpace(overrideKdc))
            {
                client.Configuration.Defaults.DnsLookupKdc = false;
                client.PinKdc(kerbCred.Domain, overrideKdc);
            }

            if (cacheToFile)
            {
                client.Configuration.Defaults.DefaultCCacheName = "krb5cc";
            }

            KrbPrincipalName cnameHint = null;

            if (includeCNameHint)
            {
                cnameHint = KrbPrincipalName.FromString(kerbCred.UserName, PrincipalNameType.NT_PRINCIPAL, kerbCred.Domain);
            }

            client.RenewTickets = true;

            using (client)
            using (kerbCred as IDisposable)
            {
                await client.Authenticate(kerbCred);

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

                var session = await client.GetServiceTicket(
                    new RequestServiceTicket
                    {
                        ServicePrincipalName = spn,
                        ApOptions = ApOptions.MutualRequired,
                        S4uTicket = s4uTicket,
                        CNameHint = cnameHint
                    }
                );

                DumpTicket(session.ApReq);

                ResetColor();

                if (!retryDH)
                {
                    try
                    {
                        await TryValidate(spn, session.ApReq, servicePassword, serviceSalt);
                    }
                    catch (Exception ex)
                    {
                        W(ex.Message, ConsoleColor.Yellow);

                        ResetColor();
                    }
                }
            }
        }

        private static void W() => W("");

        private static void W(string message)
        {
            ResetColor();
            WriteLine(message);
        }

        private static void W(string message, ConsoleColor color)
        {
            ForegroundColor = color;

            WriteLine(message);
            ResetColor();
        }

        private static async Task TryValidate(string spn, KrbApReq ticket, string servicePassword, string serviceSalt)
        {
            var encoded = ticket.EncodeApplication().ToArray();

            KerberosKey kerbKey;

            if (string.IsNullOrWhiteSpace(serviceSalt))
            {
                kerbKey = new KerberosKey(
                    "P@ssw0rd!",
                    principalName: new PrincipalName(
                        PrincipalNameType.NT_PRINCIPAL,
                        ticket.Ticket.Realm,
                        new[] { spn }
                    ),
                    saltType: SaltType.ActiveDirectoryUser
                );
            }
            else
            {
                kerbKey = new KerberosKey(
                    servicePassword,
                    salt: serviceSalt,
                    etype: ticket.Ticket.EncryptedPart.EType,
                    saltType: SaltType.ActiveDirectoryService
                );
            }

            var authenticator = new KerberosAuthenticator(new KeyTable(kerbKey));

            var validated = (KerberosIdentity)await authenticator.Authenticate(encoded);

            DumpRestrictions(validated);
        }

        private static void DumpTicket(KrbApReq ticket)
        {
            W("====== Ticket ======");

            W($"Type: {ticket.MessageType}", ConsoleColor.Green);
            W($"APOptions: {ticket.ApOptions}", ConsoleColor.Green);
            W($"Realm: {ticket.Ticket.Realm}", ConsoleColor.Green);
            W($"SName: {ticket.Ticket.SName.FullyQualifiedName}", ConsoleColor.Green);

            W();
        }

        private static void DumpRestrictions(KerberosIdentity validated)
        {
            W("=== Restrictions ===");

            W($"UserName: {validated.Name}", ConsoleColor.Green);
            W($"AuthType: {validated.AuthenticationType}", ConsoleColor.Green);
            W($"Validated by: {validated.ValidationMode}", ConsoleColor.Green);

            foreach (var kv in validated.Restrictions)
            {
                W($"Restriction: {kv.Key}", ConsoleColor.Green);

                foreach (var restriction in kv.Value)
                {
                    W($"Type: {restriction.Type}", ConsoleColor.Green);
                    W($"Value: {restriction}", ConsoleColor.Green);

                    if (restriction is PrivilegedAttributeCertificate pac)
                    {
                        W($"{pac.DelegationInformation}", ConsoleColor.Green);
                    }
                }

                W();
            }

            W("=== Claims ===");

            foreach (var claim in validated.Claims)
            {
                W($"Type: {claim.Type}", ConsoleColor.Green);
                W($"Value: {claim.Value}", ConsoleColor.Green);
                W();
            }
        }

        private static string ReadString(string label, string defaultVal = null, string[] args = null, Func<string> reader = null, bool required = true, bool prompt = true)
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

            string val = null;

            if ((required && string.IsNullOrWhiteSpace(defaultVal)) || prompt)
            {
                reader ??= ReadLine;

                val = reader();
            }
            else
            {
                W();
            }

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
                    W();
                    break;
                }
            }
            while (true);

            return masked;
        }
    }
}
