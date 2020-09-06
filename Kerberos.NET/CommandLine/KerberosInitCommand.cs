// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Security.Cryptography.Asn1;
using System.Threading.Tasks;
using Kerberos.NET.Client;
using Kerberos.NET.Configuration;
using Kerberos.NET.Credentials;

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

        [CommandLineParameter("username", FormalParameter = true, Required = true, Description = "UserPrincipalName")]
        public string UserPrincipalName { get; private set; }

        [CommandLineParameter("V", Description = "Verbose")]
        public bool Verbose { get; private set; }

        [CommandLineParameter("l|lifetime", Description = "LifeTime")]
        public TimeSpan? Lifetime { get; private set; }

        [CommandLineParameter("s|start-time", Description = "StartTime")]
        public TimeSpan? StarTime { get; private set; }

        [CommandLineParameter("f|forwardable", Description = "Forward")]
        public bool Forward { get; private set; }

        [CommandLineParameter("F|no-forwardable", Description = "NoForward")]
        public bool NoForward { get => !this.Forward; private set => this.Forward = !value; }

        [CommandLineParameter("p|proxiable", Description = "Proxy")]
        public bool Proxy { get; private set; }

        [CommandLineParameter("p|no-proxy", Description = "NoProxy")]
        public bool NoProxy { get => !this.Proxy; private set => this.Proxy = !value; }

        [CommandLineParameter("a", EnforceCasing = false, Description = "IncludeAddresses")]
        public bool IncludeAddresses { get; private set; }

        [CommandLineParameter("C", Description = "Canonicalize")]
        public bool Canonicalize { get; private set; }

        [CommandLineParameter("E|enterprise", Description = "Enterprise")]
        public bool Enterprise { get; private set; }

        [CommandLineParameter("v|validate", Description = "Validate")]
        public bool Validate { get; private set; }

        [CommandLineParameter("R|renew", Description = "Renew")]
        public bool Renew { get; private set; }

        [CommandLineParameter("renewable", Description = "Renewable")]
        public bool Renewable { get; private set; }

        [CommandLineParameter("r|renewable-life", Description = "RenewLifetime")]
        public TimeSpan? RenewLifetime { get; private set; }

        [CommandLineParameter("t|keytab-name", Description = "Keytab")]
        public string Keytab { get; private set; }

        [CommandLineParameter("k|use-keytab", Description = "Usekeytab")]
        public bool UseKeytab { get; private set; }

        [CommandLineParameter("n|anonymous", Description = "Anonymous")]
        public bool Anonymous { get; private set; }

        [CommandLineParameter("T", Description = "ArmorCache")]
        public string ArmorCache { get; private set; }

        [CommandLineParameter("c|cache", Description = "Cache")]
        public string Cache { get; private set; }

        [CommandLineParameter("S|server", Description = "Servicename")]
        public string ServiceName { get; private set; }

        public override async Task<bool> Execute()
        {
            if (await base.Execute())
            {
                return true;
            }

            var config = Krb5Config.CurrentUser();

            if (!string.IsNullOrWhiteSpace(this.Cache))
            {
                config.Defaults.DefaultCCacheName = this.Cache;
            }

            var client = new KerberosClient(config);

            var cred = ParseCredential();

            await client.Authenticate(cred);

            if (!string.IsNullOrWhiteSpace(this.ServiceName))
            {
                await client.GetServiceTicket(this.ServiceName);
            }

            var klist = new KerberosListCommand(this.Parameters) { IO = this.IO };

            await klist.Execute();

            return true;
        }

        private KerberosCredential ParseCredential()
        {
            if (string.IsNullOrWhiteSpace(this.UserPrincipalName))
            {
                this.UserPrincipalName = Environment.UserName;
            }

            string formattedUsername = this.UserPrincipalName;

            if (!formattedUsername.Contains("@"))
            {
                formattedUsername = $"{formattedUsername}@{this.DefaultDomain}";
            }

            this.IO.Writer.Write(
                SR.Resource("CommandLine_KInit_PassPrompt",
                    formattedUsername
                )
            );

            var password = ReadMasked();

            var cred = new KerberosPasswordCredential(this.UserPrincipalName, password, this.DefaultDomain);

            return cred;
        }

        private string ReadMasked()
        {
            var masked = "";

            do
            {
                ConsoleKeyInfo key = this.IO.ReadKey();

                if (key.Key != ConsoleKey.Backspace &&
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
    }
}
