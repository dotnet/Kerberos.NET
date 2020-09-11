// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Asn1;
using System.Threading.Tasks;
using Kerberos.NET.Client;
using Kerberos.NET.Entities;

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

            this.IO.Writer.WriteLine();

            var client = this.CreateClient(verbose: this.Verbose);

            if (!string.IsNullOrWhiteSpace(this.Cache))
            {
                if (!this.Cache.StartsWith("FILE:", StringComparison.OrdinalIgnoreCase))
                {
                    this.Cache = "FILE:" + this.Cache;
                }

                client.Configuration.Defaults.DefaultCCacheName = this.Cache;
            }

            if (this.Purge)
            {
                await this.PurgeTickets();
            }

            if (!string.IsNullOrWhiteSpace(this.ServicePrincipalName))
            {
                await GetServiceTicket(client);
            }

            this.ListTickets(client.Configuration.Defaults.DefaultCCacheName);

            return true;
        }

        private async Task GetServiceTicket(KerberosClient client)
        {
            try
            {
                await client.GetServiceTicket(this.ServicePrincipalName);
            }
            catch (AggregateException aex)
            {
                foreach (var kex in aex.InnerExceptions.OfType<KerberosProtocolException>())
                {
                    if (kex.Error.ErrorCode == KerberosErrorCode.KRB_AP_ERR_TKT_EXPIRED)
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

            this.IO.Writer.WriteLine("{0}: {1}", SR.Resource("CommandLine_KList_Count"), tickets.Length);
            this.IO.Writer.WriteLine();

            for (var i = 0; i < tickets.Length; i++)
            {
                var ticket = tickets[i];

                KrbTicket decodedTicket = TryParseTicket(ticket.Ticket);

                var properties = new List<(string, string)>
                {
                    ("CommandLine_KList_Client", $"{ticket.Client.FullyQualifiedName} @ {ticket.Client.Realm}"),
                    ("CommandLine_KList_Server", $"{ticket.Server.FullyQualifiedName} @ {ticket.Server.Realm}"),
                    ("CommandLine_KList_TicketEType", $"{decodedTicket?.EncryptedPart?.EType.ToString()}"),
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

        private static KrbTicket TryParseTicket(ReadOnlyMemory<byte> ticket)
        {
            if (ticket.Length <= 0)
            {
                return null;
            }

            try
            {
                return KrbTicket.DecodeApplication(ticket);
            }
            catch (CryptographicException)
            {
            }

            return null;
        }

        private async Task PurgeTickets()
        {
            var destroy = this.CreateCommand<KerberosDestroyCommand>();

            await destroy.Execute();
        }
    }
}
