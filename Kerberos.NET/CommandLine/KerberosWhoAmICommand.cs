// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using Kerberos.NET.Client;
using System;
using System.IO;
using System.Security.Cryptography.Asn1;
using System.Threading.Tasks;

namespace Kerberos.NET.CommandLine
{
    [CommandLineCommand("whoami", Description = "KerberosWhoAmI")]
    public class KerberosWhoAmI : BaseCommand
    {
        public KerberosWhoAmI(CommandLineParameters parameters)
            : base(parameters)
        {
        }

        [CommandLineParameter("c|cache", Description = "Cache")]
        public string Cache { get; set; }

        public override async Task<bool> Execute()
        {
            if (await base.Execute())
            {
                return true;
            }

            var client = this.CreateClient();

            if (!string.IsNullOrWhiteSpace(this.Cache))
            {
                client.Configuration.Defaults.DefaultCCacheName = this.Cache;
            }

            await this.S4u2Self(client);

            return true;
        }

        private async Task S4u2Self(KerberosClient client)
        {
            var myTgtEntry = client.Cache.GetCacheItem<KerberosClientCacheEntry>($"krbtgt/{client.DefaultDomain}");

            var myTgt = myTgtEntry.KdcResponse.Ticket;

            var result = await client.GetServiceTicket(new RequestServiceTicket
            {
                S4uTarget = client.UserPrincipalName,
                ServicePrincipalName = client.UserPrincipalName
                UserToUserTicket = myTgt
            });

            ;
        }
    }
}
