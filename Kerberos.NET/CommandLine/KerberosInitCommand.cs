// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.Asn1;
using System.Threading.Tasks;
using Kerberos.NET.Client;
using Kerberos.NET.Configuration;
using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;

namespace Kerberos.NET.CommandLine
{
    [CommandLineCommand("kinit", Description = "KerberosInit")]
    public class KerberosInitCommand : BaseCommand
    {
        public KerberosInitCommand(CommandLineParameters parameters)
            : base(parameters)
        {
        }

        public string DefaultDomain => Environment.GetEnvironmentVariable("USERDNSDOMAIN");

        [CommandLineParameter("principal",
            FormalParameter = true,
            Required = true,
            Description = "UserPrincipalName")]
        public string UserPrincipalName { get; set; }

        [CommandLineParameter("realm", Description = "RealmName")]
        public string Realm { get; set; }

        [CommandLineParameter("V", Description = "Verbose")]
        public bool Verbose { get; set; }

        [CommandLineParameter("l|lifetime", Description = "LifeTime")]
        public TimeSpan? Lifetime { get; set; }

        [CommandLineParameter("s|start-time", Description = "StartTime")]
        public TimeSpan? StarTime { get; set; }

        [CommandLineParameter("f|forwardable", Description = "Forward")]
        public bool? Forward { get; set; }

        [CommandLineParameter("F|no-forwardable", Description = "NoForward")]
        public bool? NoForward { get => !this.Forward; private set => this.Forward = !value; }

        [CommandLineParameter("p|proxiable", Description = "Proxy")]
        public bool? Proxy { get; set; }

        [CommandLineParameter("P|no-proxy", Description = "NoProxy")]
        public bool? NoProxy { get => !this.Proxy; private set => this.Proxy = !value; }

        [CommandLineParameter("a", EnforceCasing = false, Description = "IncludeAddresses")]
        public bool? IncludeAddresses { get; set; }

        [CommandLineParameter("C", Description = "Canonicalize")]
        public bool? Canonicalize { get; set; }

        [CommandLineParameter("E|enterprise", Description = "Enterprise")]
        public bool? Enterprise { get; set; }

        [CommandLineParameter("v|validate", Description = "Validate")]
        public bool? Validate { get; set; }

        [CommandLineParameter("R|renew", Description = "Renew")]
        public bool? Renew { get; set; }

        [CommandLineParameter("renewable", Description = "Renewable")]
        public bool? Renewable { get; set; }

        [CommandLineParameter("r|renewable-life", Description = "RenewLifetime")]
        public TimeSpan? RenewLifetime { get; set; }

        [CommandLineParameter("t|keytab-name", Description = "Keytab")]
        public string Keytab { get; set; }

        [CommandLineParameter("k|use-keytab", Description = "Usekeytab")]
        public bool UseKeytab { get; set; }

        [CommandLineParameter("n|anonymous", Description = "Anonymous")]
        public bool Anonymous { get; set; }

        [CommandLineParameter("T", Description = "ArmorCache")]
        public string ArmorCache { get; set; }

        [CommandLineParameter("c|cache", Description = "Cache")]
        public string Cache { get; set; }

        [CommandLineParameter("S|server", Description = "Servicename")]
        public string ServiceName { get; set; }

        [CommandLineParameter("X|ext", Description = "Extension")]
        public ICollection<string> Extensions { get; private set; } = new List<string>();

        [CommandLineParameter("e|enctypes", Description = "ETypes")]
        public ICollection<EncryptionType> ETypes { get; private set; } = new List<EncryptionType>();

        [CommandLineParameter("extra-addresses", Description = "ExtraAddr")]
        public ICollection<string> ExtraAddresses { get; private set; } = new List<string>();

        [CommandLineParameter("C|cert|pk-user", Description = "Certificate")]
        public string Certificate { get; set; }

        [CommandLineParameter("kdc|kdc-hostname", Description = "KdcHostname")]
        public string KdcHostname { get; set; }

        [CommandLineParameter("request-pac", Description = "RequestPac")]
        public bool? RequestPac { get; set; }

        [CommandLineParameter("rst|reset", Description = "Reset")]
        public bool Reset { get; set; }

        public override async Task<bool> Execute()
        {
            if (await base.Execute())
            {
                return true;
            }

            this.IO.Writer.WriteLine();

            var client = this.CreateClient(verbose: this.Verbose);

            if (this.Reset)
            {
                client.ResetConnections();
            }

            if (!string.IsNullOrWhiteSpace(this.Cache))
            {
                if (!this.Cache.StartsWith("FILE:", StringComparison.OrdinalIgnoreCase))
                {
                    this.Cache = "FILE:" + this.Cache;
                }

                client.Configuration.Defaults.DefaultCCacheName = this.Cache;
            }

            this.SetClientProperties(client);

            var cred = ParseCredential(client.Configuration);

            if (cred == null)
            {
                this.IO.Writer.WriteLine(SR.Resource("CommandLine_KerberosInitCommand_CredNotFound"));
                this.IO.Writer.WriteLine();
                return true;
            }

            if (!string.IsNullOrWhiteSpace(this.KdcHostname))
            {
                client.PinKdc(cred.Domain, this.KdcHostname);
            }

            await client.Authenticate(cred);

            if (!string.IsNullOrWhiteSpace(this.ServiceName))
            {
                await client.GetServiceTicket(this.ServiceName);
            }

            var klist = this.CreateCommand<KerberosListCommand>();

            klist.Cache = this.Cache;

            await klist.Execute();

            return true;
        }

        private void SetClientProperties(KerberosClient client)
        {
            SetClientProperty(this.Proxy, client, AuthenticationOptions.Proxy);
            SetClientProperty(this.Renew, client, AuthenticationOptions.Renew);
            SetClientProperty(this.Renewable, client, AuthenticationOptions.Renewable);
            SetClientProperty(this.Canonicalize, client, AuthenticationOptions.Canonicalize);

            if (this.RenewLifetime.HasValue)
            {
                client.Configuration.Defaults.RenewLifetime = this.RenewLifetime.Value;
            }

            if (this.ETypes?.Any() ?? false)
            {
                client.Configuration.Defaults.DefaultTicketEncTypes.Clear();
                client.Configuration.Defaults.DefaultTgsEncTypes.Clear();

                foreach (var etype in this.ETypes)
                {
                    client.Configuration.Defaults.DefaultTicketEncTypes.Add(etype);
                    client.Configuration.Defaults.DefaultTgsEncTypes.Add(etype);
                }
            }

            if (this.ExtraAddresses?.Any() ?? false)
            {
                client.Configuration.Defaults.ExtraAddresses.Clear();

                foreach (var addr in this.ExtraAddresses)
                {
                    client.Configuration.Defaults.ExtraAddresses.Add(addr);
                }
            }

            if (this.RequestPac.HasValue)
            {
                client.Configuration.Defaults.RequestPac = this.RequestPac.Value;
            }
        }

        private static void SetClientProperty(
            bool? flag,
            KerberosClient client,
            AuthenticationOptions option
        )
        {
            if (!flag.HasValue)
            {
                return;
            }

            if (flag.Value)
            {
                client.AuthenticationOptions |= option;
            }
            else
            {
                client.AuthenticationOptions &= ~option;
            }
        }

        private KerberosCredential ParseCredential(Krb5Config config)
        {
            var domain = this.DefaultDomain;

            if (!string.IsNullOrWhiteSpace(this.Realm))
            {
                domain = this.Realm;
            }

            if (string.IsNullOrWhiteSpace(this.UserPrincipalName))
            {
                this.UserPrincipalName = Environment.UserName;
            }

            if (!this.UserPrincipalName.Contains("@"))
            {
                this.UserPrincipalName = $"{this.UserPrincipalName}@{domain}";
            }

            if (!string.IsNullOrWhiteSpace(this.Certificate))
            {
                return KerberosAsymmetricCredential.Get(this.Certificate, domain);
            }
            else if (this.UseKeytab || !string.IsNullOrWhiteSpace(this.Keytab))
            {
                var keytab = config.Defaults.DefaultClientKeytabName;

                if (!string.IsNullOrWhiteSpace(this.Keytab))
                {
                    keytab = this.Keytab;
                }

                var kt = new KeyTable(File.ReadAllBytes(Environment.ExpandEnvironmentVariables(keytab)));

                return new KeytabCredential(this.UserPrincipalName, kt, domain);
            }
            else
            {
                this.IO.Writer.Write(
                    SR.Resource("CommandLine_KInit_PassPrompt",
                        this.UserPrincipalName
                    )
                );

                var password = ReadMasked();

                if (string.IsNullOrWhiteSpace(password))
                {
                    return null;
                }

                var cred = new KerberosPasswordCredential(this.UserPrincipalName, password, domain);

                return cred;
            }
        }

        private string ReadMasked()
        {
            var masked = "";

            try
            {
                this.IO.HookCtrlC(true);

                do
                {
                    ConsoleKeyInfo key = this.IO.ReadKey();

                    if (key.Modifiers.HasFlag(ConsoleModifiers.Control) && key.Key == ConsoleKey.C)
                    {
                        this.IO.Writer.WriteLine();
                        return null;
                    }
                    else if (key.Key != ConsoleKey.Backspace &&
                        key.Key != ConsoleKey.Enter &&
                        !char.IsControl(key.KeyChar))
                    {
                        masked += key.KeyChar;

                        this.IO.Writer.Write("*");
                    }
                    else if (key.Key == ConsoleKey.Backspace && masked.Length > 0)
                    {
                        this.IO.Writer.Write("\b \b");
                        masked = masked.Substring(0, masked.Length - 1);
                    }
                    else if (key.Key == ConsoleKey.Enter)
                    {
                        this.IO.Writer.WriteLine();
                        break;
                    }
                }
                while (true);

                return masked;
            }
            finally
            {
                this.IO.HookCtrlC(false);
            }
        }
    }
}
