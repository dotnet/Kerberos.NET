// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Globalization;
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
        public bool Purge { get; set; }

        [CommandLineParameter("c|cache", Description = "Cache")]
        public string Cache { get; set; }

        [CommandLineParameter("config", Description = "Config")]
        public bool ListConfig { get; set; }

        [CommandLineParameter("s|t|test", Description = "Test")]
        public bool Test { get; set; }

        [CommandLineParameter("f", Description = "ShortFlags")]
        public bool ShortFormFlags { get; set; }

        [CommandLineParameter("v|verbose", EnforceCasing = false, Description = "Verbose")]
        public bool Verbose { get; set; }

        [CommandLineParameter("l|list-caches", Description = "ListCaches")]
        public bool ListCaches { get; set; }

        [CommandLineParameter("get", Description = "Get")]
        public string ServicePrincipalName { get; set; }

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

            if (this.Purge)
            {
                await this.PurgeTickets();
            }

            if (!string.IsNullOrWhiteSpace(this.ServicePrincipalName))
            {
                await GetServiceTicket(client.Configuration);
            }

            this.ListTickets(client.Configuration.Defaults.DefaultCCacheName);

            if (this.ListConfig)
            {
                this.ListConfiguration(client.Configuration);
            }

            return true;
        }

        private void ListConfiguration(Krb5Config config)
        {
            var configStr = config.Serialize();

            this.IO.Writer.WriteLine(configStr);
        }

        private async Task GetServiceTicket(Krb5Config config)
        {
            var client = this.CreateClient();

            try
            {
                await client.GetServiceTicket(this.ServicePrincipalName);
            }
            catch (AggregateException aex)
            {
                foreach (var kex in aex.InnerExceptions.OfType<KerberosProtocolException>())
                {
                    if (kex.Error.ErrorCode == Entities.KerberosErrorCode.KRB_AP_ERR_TKT_EXPIRED)
                    {
                        await PurgeTickets();
                        await client.GetServiceTicket(this.ServicePrincipalName);
                        break;
                    }
                }
            }
        }

        private void ListTickets(string cache)
        {
            TicketCacheBase.TryParseCacheType(cache, out _, out string path);

            var ticketCache = new Krb5TicketCache(path);

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

                var ticketEntryNumber = string.Format("#{0}>", i);

                var max = properties.Max(p => p.Item1.Length);

                bool first = true;

                foreach (var prop in properties)
                {
                    var key = string.Format("{0}: ", SR.Resource(prop.Item1)).PadLeft(max - 1).PadRight(max);

                    if (first)
                    {
                        key = ticketEntryNumber + key.Substring(ticketEntryNumber.Length);

                        first = false;
                    }

                    this.IO.Writer.Write(key);
                    this.IO.Writer.WriteLine(prop.Item2);
                }

                this.IO.Writer.WriteLine();
            }
        }

        private async Task PurgeTickets()
        {
            KerberosDestroyCommand destroy = new KerberosDestroyCommand(this.Parameters);

            await destroy.Execute();
        }
    }
}
