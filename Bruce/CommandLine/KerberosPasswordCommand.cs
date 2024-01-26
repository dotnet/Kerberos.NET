// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using Kerberos.NET.Configuration;
using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Kerberos.NET.CommandLine
{
    [CommandLineCommand("kpasswd|passwd", Description = "KerberosPassword")]
    public class KerberosPasswordCommand : BaseCommand
    {
        public KerberosPasswordCommand(CommandLineParameters parameters)
            : base(parameters)
        {
        }

        [CommandLineParameter("config", Description = "Config")]
        public override string ConfigurationPath { get; set; }

        [CommandLineParameter("principal",
            Required = true,
            Description = "UserPrincipalName")]
        public override string PrincipalName { get; set; }

        [CommandLineParameter("realm", Description = "RealmName")]
        public override string Realm { get; set; }

        [CommandLineParameter("password", Description = "Password")]
        public string Password { get; set; }

        [CommandLineParameter("targname", Description = "TargName")]
        public string TargName { get; set; }

        [CommandLineParameter("targrealm", Description = "TargRealm")]
        public string TargRealm { get; set; }

        [CommandLineParameter("newpassword", Description = "NewPassword")]
        public string NewPassword { get; set; }

        [CommandLineParameter("verbose", Description = "Verbose")]
        public override bool Verbose { get; set; }

        public override async Task<bool> Execute()
        {
            if (await base.Execute())
            {
                return true;
            }

            this.WriteLine();

            var client = this.CreateClient(verbose: this.Verbose);
            var logger = this.Verbose ? this.IO.CreateVerboseLogger(labels: true) : NullLoggerFactory.Instance;

            // Prompt for user password
            string password = this.Password;
            if (string.IsNullOrWhiteSpace(password))
            {
                this.Write(SR.Resource("CommandLine_KerberosPassword_PassPrompt", this.PrincipalName));

                password = this.ReadMasked();
            }

            if (string.IsNullOrWhiteSpace(password))
            {
                this.WriteLine(SR.Resource("CommandLine_KerberosPassword_CredNotFound"));
                this.WriteLine();
                return true;
            }

            // Provides better UX if bad password fails before prompting for new password
            var cred = new KerberosPasswordCredential(this.PrincipalName, password, this.Realm);
            await client.Authenticate(cred);

            // Must pass targRealm with targName or it will fail on Active Directory
            var targRealm = string.IsNullOrWhiteSpace(this.TargRealm) ? client.DefaultDomain : this.TargRealm;

            // Parsing the principal provides a better prompt string
            var targPrinc = KrbPrincipalName.FromString(this.TargName, null, targRealm);

            // Prompt for new password
            string newPassword = this.NewPassword;
            if (string.IsNullOrWhiteSpace(newPassword))
            {
                this.Write(SR.Resource("CommandLine_KerberosPassword_NewPassPrompt",
                    string.IsNullOrWhiteSpace(this.TargName) ? this.PrincipalName : targPrinc.FullyQualifiedName));

                newPassword = this.ReadMasked();
            }

            if (string.IsNullOrWhiteSpace(newPassword))
            {
                this.WriteLine(SR.Resource("CommandLine_KerberosPassword_CredNotFound"));
                this.WriteLine();
                return true;
            }

            // Change password or set password based on TargName parameter
            this.WriteLine();
            if (string.IsNullOrWhiteSpace(this.TargName))
            {
                this.WriteLine(SR.Resource("CommandLine_KerberosPassword_Changing", this.PrincipalName));
                await client.ChangePassword(cred, newPassword);
                this.WriteLine(SR.Resource("CommandLine_KerberosPassword_ChangeSuccess", this.PrincipalName));
            }
            else
            {
                this.WriteLine(SR.Resource("CommandLine_KerberosPassword_Setting", targPrinc));
                await client.SetPassword(cred, this.TargName, targRealm, newPassword);
                this.WriteLine(SR.Resource("CommandLine_KerberosPassword_SetSuccess", this.TargName));
            }

            return true;
        }

        private void WriteFailure(ILoggerFactory logger, AggregateException gex)
        {
            if (this.Verbose)
            {
                this.WriteLine();
            }

            ILogger errorLog;

            if (this.Verbose)
            {
                errorLog = logger.CreateLogger("Error");
            }
            else
            {
                errorLog = this.IO.CreateVerboseLogger().CreateLogger("Error");
            }

            foreach (var ex in gex.InnerExceptions)
            {
                errorLog.LogDebug(ex.Message);
            }
        }
    }
}
