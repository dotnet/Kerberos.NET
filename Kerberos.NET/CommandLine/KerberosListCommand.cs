// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography.Asn1;
using System.Threading.Tasks;
using Kerberos.NET.Client;
using Kerberos.NET.Configuration;

namespace Kerberos.NET.CommandLine
{
    [CommandLineCommand("klist", Description = "KerberosList")]
    public class KerberosListCommand : BaseCommand
    {
        public KerberosListCommand(CommandLineParameters parameters)
            : base(parameters)
        {
        }

        [CommandLineParameter("p|purge|clear", Description = "Purge")]
        public bool Purge { get; private set; }

        [CommandLineParameter("c|cache", Description = "Cache")]
        public string Cache { get; private set; }

        [CommandLineParameter("config", Description = "Config")]
        public bool ListConfig { get; private set; }

        [CommandLineParameter("s|t|test", Description = "Test")]
        public bool Test { get; private set; }

        [CommandLineParameter("f", Description = "ShortFlags")]
        public bool ShortFormFlags { get; private set; }

        [CommandLineParameter("v|verbose", EnforceCasing = false, Description = "Verbose")]
        public bool Verbose { get; private set; }

        [CommandLineParameter("l|list-caches", Description = "ListCaches")]
        public bool ListCaches { get; private set; }

        [CommandLineParameter("get", Description = "Get")]
        public string ServicePrincipalName { get; private set; }

        public override async Task<bool> Execute()
        {
            if (await base.Execute())
            {
                return true;
            }

            var config = Krb5Config.CurrentUser();

            var cache = config.Defaults.DefaultCCacheName;

            if (!string.IsNullOrWhiteSpace(this.Cache))
            {
                cache = this.Cache;
            }

            if (this.Purge)
            {
                this.PurgeTickets(cache);
            }

            if (!string.IsNullOrWhiteSpace(this.ServicePrincipalName))
            {
                config.Defaults.DefaultCCacheName = cache;

                await GetServiceTicket(config);
            }

            this.ListTickets(cache);

            if (this.ListConfig)
            {
                var configStr = config.Serialize();

                this.IO.Writer.WriteLine(configStr);
            }

            return true;
        }

        private async Task GetServiceTicket(Krb5Config config)
        {
            var client = new KerberosClient(config);

            await client.GetServiceTicket(this.ServicePrincipalName);
        }

        private void ListTickets(string cache)
        {
            var ticketCache = new Krb5TicketCache(cache);

            var tickets = ticketCache.CacheInternals.ToArray();

            this.IO.Writer.WriteLine();
            this.IO.Writer.WriteLine("Ticket Count: {0}", tickets.Length);
            this.IO.Writer.WriteLine();

            for (var i = 0; i < tickets.Length; i++)
            {
                var ticket = tickets[i];

                var properties = new List<(string, string)>
                {
                    ("CommandLine_KList_Client", $"{ticket.Client.FullyQualifiedName} @ {ticket.Client.Realm}"),
                    ("CommandLine_KList_Server", $"{ticket.Server.FullyQualifiedName} @ {ticket.Server.Realm}"),
                    ("CommandLine_KList_Flags", ticket.Flags.ToString()),
                    ("CommandLine_KList_Start", ticket.AuthTime.ToLocalTime().ToString(CultureInfo.CurrentCulture)),
                    ("CommandLine_KList_End", ticket.EndTime.ToLocalTime().ToString(CultureInfo.CurrentCulture)),
                    ("CommandLine_KList_RenewTime", ticket.RenewTill.ToLocalTime().ToString(CultureInfo.CurrentCulture))
                };

                this.IO.Writer.WriteLine("#{0}>", i);

                var max = properties.Max(p => p.Item1.Length);

                foreach (var prop in properties)
                {
                    this.IO.Writer.Write(string.Format("{0}: ", SR.Resource(prop.Item1)).PadLeft(max).PadRight(max));
                    this.IO.Writer.WriteLine(prop.Item2);
                }

                this.IO.Writer.WriteLine();
            }
        }

        private void PurgeTickets(string cache)
        {
            try
            {
                File.Delete(Environment.ExpandEnvironmentVariables(cache));
            }
            catch (Exception ex)
            {
                this.IO.Writer.WriteLine(ex.Message);
            }
        }
    }
}
