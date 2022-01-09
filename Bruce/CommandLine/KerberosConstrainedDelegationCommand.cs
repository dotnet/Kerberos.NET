using Kerberos.NET.Client;
using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using System;
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

        [CommandLineParameter("realm", Description = "Realm")]
        public override string Realm { get; set; }

        [CommandLineParameter("verbose", Description = "Verbose")]
        public override bool Verbose { get; set; }

        [CommandLineParameter("spn", Description = "ServicePrincipalName")]
        public string ServicePrincipalName { get; set; }

        [CommandLineParameter("spn-pass", Description = "ServicePrincipalNamePassword")]
        public string ServicePrincipalNamePassword { get; set; }

        [CommandLineParameter("sam", Description = "SamAccountName")]
        public string SamAccountName { get; set; }

        [CommandLineParameter("delegated", Description = "Delegated")]
        public string Delegated { get; set; }

        public override async Task<bool> Execute()
        {
            if (await base.Execute())
            {
                return true;
            }

            this.WriteLine();

            var client = this.CreateClient(verbose: this.Verbose);

            this.WriteLine(3, "Double Hop: {Client} => {MiddleBox} => {Backend}", client.UserPrincipalName, this.ServicePrincipalName, this.Delegated);
            this.WriteLine();

            var serviceTicket = await client.GetServiceTicket(new RequestServiceTicket { ServicePrincipalName = this.ServicePrincipalName });

            this.WriteHeader("======== Client ========");
            this.WriteLine();

            this.WriteLine(3, "{User} @ {Realm} => {Spn}", client.UserPrincipalName, client.DefaultDomain, serviceTicket.ApReq.Ticket.SName.FullyQualifiedName);
            this.WriteLine();

            this.WriteHeader("======== Middle box ========");

            var serviceCred = new KerberosPasswordCredential(this.SamAccountName, this.ServicePrincipalNamePassword, serviceTicket.ApReq.Ticket.Realm);

            var ping = await KerberosPing.Ping(serviceCred, client);

            serviceCred.IncludePreAuthenticationHints(ping.Error.DecodePreAuthentication());

            var keytab = new KeyTable(serviceCred.CreateKey());

            var authenticator = new KerberosAuthenticator(this.SamAccountName, keytab, client.Configuration);

            var identity = await authenticator.Authenticate(serviceTicket.ApReq.EncodeGssApi()) as KerberosIdentity;

            var whoami = this.CreateCommand<KerberosWhoAmI>();
            whoami.All = true;
            whoami.DescribeTicket(identity);

            this.WriteLine();

            this.WriteHeader("======== Backend ========");

            var delegated = await identity.GetDelegatedServiceTicket(this.Delegated);

            this.DescribeApReq(delegated);

            return true;
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
