// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using Kerberos.NET.Client;
using System;
using System.IO;
using System.Threading.Tasks;

namespace Kerberos.NET.CommandLine
{
    [CommandLineCommand("kdestroy", Description = "KerberosDestroy")]
    public class KerberosDestroyCommand : BaseCommand
    {
        public KerberosDestroyCommand(CommandLineParameters parameters)
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

            this.PurgeTickets(client);

            return true;
        }

        private void PurgeTickets(KerberosClient client)
        {
            try
            {
                if (client.Cache is ITicketCache2 cache)
                {
                    cache.PurgeTickets();
                }

                this.WriteLine(SR.Resource("CommandLine_KerberosDestroy_Deleted"));
            }
            catch (Exception ex)
            {
                this.WriteLine(string.Format("{0}{{Error}}", SR.Resource("CommandLine_KerberosDestroy_Error")), ex.Message);
            }
        }
    }
}
