using Kerberos.NET.Client;
using Kerberos.NET.Configuration;
using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Microsoft.Extensions.Logging;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Kerberos.NET.CommandLine.CommandLine
{
    [CommandLineCommand("kcd", Description = "KerberosConstrainedDelegation")]
    public class KerberosConstrainedDelegationCommand : BaseCommand
    {
        public KerberosConstrainedDelegationCommand(CommandLineParameters parameters)
            : base(parameters)
        {
        }

        [CommandLineParameter("principal",
            FormalParameter = true,
            Required = true,
            Description = "UserPrincipalName")]
        public override string PrincipalName { get; set; }

        [CommandLineParameter("realm", Description = "Realm", Required = true)]
        public override string Realm { get; set; }

        [CommandLineParameter("verbose", Description = "Verbose")]
        public override bool Verbose { get; set; }

        [CommandLineParameter("spn", Description = "ServicePrincipalName", Required = true)]
        public string ServicePrincipalName { get; set; }

        [CommandLineParameter("spn-pass", Description = "ServicePrincipalNamePassword", Required = true)]
        public string ServicePrincipalNamePassword { get; set; }

        [CommandLineParameter("spn-sam", Description = "ServicePrincipalSamAccountName", Required = true)]
        public string ServicePrincipalSamAccountName { get; set; }

        [CommandLineParameter("delegated", Description = "Delegated", Required = true)]
        public string Delegated { get; set; }

        public override async Task<bool> Execute()
        {
            if (await base.Execute())
            {
                return true;
            }

            var client = this.CreateClient(verbose: this.Verbose);
            ILoggerFactory logger = this.Verbose ? this.IO.CreateVerboseLogger(true) : null;

            this.WriteLine();
            this.WriteLine(2, "Double Hop: {Client} => {MiddleBox} => {Backend}", client.UserPrincipalName, this.ServicePrincipalName, this.Delegated);
            this.WriteLine();

            var serviceTicket = await client.GetServiceTicket(new RequestServiceTicket { ServicePrincipalName = this.ServicePrincipalName });

            if (this.Verbose)
            {
                this.WriteLine();
            }

            this.WriteHeader("======== Client ========");
            this.WriteLine();

            this.WriteLine(2, "{User} @ {Realm} => {Spn}", client.UserPrincipalName, client.DefaultDomain, serviceTicket.ApReq.Ticket.SName.FullyQualifiedName);
            this.WriteLine();

            this.WriteHeader("======== Middle box ========");

            if (this.Verbose)
            {
                this.WriteLine();
            }

            var identity = await this.ProcessAsMiddleBox(client.Configuration, logger, serviceTicket);

            var whoami = this.CreateCommand<KerberosWhoAmI>();
            whoami.Verbose = this.Verbose;
            whoami.All = true;
            whoami.DescribeTicket(identity);

            this.WriteLine();

            this.WriteHeader("======== Backend ========");

            if (this.Verbose)
            {
                this.WriteLine();
            }

            var delegated = await identity.GetDelegatedServiceTicket(this.Delegated);

            this.DescribeApReq(delegated);

            return true;
        }

        private async Task<KerberosIdentity> ProcessAsMiddleBox(Krb5Config config, ILoggerFactory logger, ApplicationSessionContext serviceTicket)
        {
            var serviceCred = new KerberosPasswordCredential(this.ServicePrincipalSamAccountName, this.ServicePrincipalNamePassword, serviceTicket.ApReq.Ticket.Realm);

            var ping = await KerberosPing.Ping(serviceCred, config, logger);

            serviceCred.IncludePreAuthenticationHints(ping.Error.DecodePreAuthentication());

            var keytab = new KeyTable(serviceCred.CreateKey());

            var authenticator = new KerberosAuthenticator(this.ServicePrincipalSamAccountName, keytab, config, logger);

            var identity = await authenticator.Authenticate(serviceTicket.ApReq.EncodeGssApi()) as KerberosIdentity;
            return identity;
        }

        private void DescribeApReq(ApplicationSessionContext delegated)
        {
            var properties = new List<(string, object)>()
            { };

            GetObjectProperties(
                new object[]
                {
                    delegated,
                    delegated.ApReq,
                    delegated.ApReq.Ticket,
                    delegated.ApReq.Ticket.SName,
                    delegated.ApReq.Ticket.EncryptedPart,
                    delegated.ApReq.Authenticator,
                    delegated.SessionKey
                },
                properties
            );

            this.WriteProperties(properties);
        }
    }
}
