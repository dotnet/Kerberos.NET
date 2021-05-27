// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
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
        public override bool Verbose { get; set; }

        [CommandLineParameter("l|list-caches", Description = "ListCaches")]
        public bool ListCaches { get; set; }

        [CommandLineParameter("get", Description = "Get")]
        public string ServicePrincipalName { get; set; }

        [CommandLineParameter("d|debug", Description = "DescribeClient")]
        public bool DescribeClient { get; set; }

        [CommandLineParameter("tgt", Description = "ShowTgt")]
        public bool ShowTgt { get; set; }

        public override async Task<bool> Execute()
        {
            if (await base.Execute())
            {
                return true;
            }

            this.WriteLine();

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
                await this.GetServiceTicket(client);
            }

            this.ListTickets(client.Configuration.Defaults.DefaultCCacheName);

            if (this.DescribeClient)
            {
                this.DescribeClientDetails(client);
            }

            if (this.ShowTgt)
            {
                this.ShowTgtDetails(client);
            }

            return true;
        }

        private void ShowTgtDetails(KerberosClient client)
        {
            var myTgtEntry = client.Cache.GetCacheItem<KerberosClientCacheEntry>($"krbtgt/{client.DefaultDomain}");

            var myTgt = myTgtEntry.KdcResponse?.Ticket;

            if (myTgt == null)
            {
                this.WriteHeader(SR.Resource("CommandLine_WhoAmI_NoTgt"));
                return;
            }

            this.WriteLine();
            this.WriteHeader("Ticket Granting Ticket");
            this.WriteLine();

            this.WriteLine(2, myTgtEntry.KdcResponse.Ticket.EncodeApplication());
        }

        private void DescribeClientDetails(KerberosClient client)
        {
            this.WriteLine();
            this.WriteHeader(SR.Resource("CommandLine_KList_ClientDetails"));

            this.WriteLine();

            this.IO.ListProperties(client);
        }

        private async Task GetServiceTicket(KerberosClient client)
        {
            try
            {
                await client.GetServiceTicket(this.ServicePrincipalName);
            }
            catch (AggregateException aex)
            {
                ICollection<Exception> exceptions = aex.InnerExceptions?.Where(e => e != null)?.ToList();

                if (exceptions == null)
                {
                    exceptions = new List<Exception>();

                    if (aex.InnerException != null)
                    {
                        exceptions.Add(aex.InnerException);
                    }
                }

                foreach (var ex in exceptions.Where(e => e != null))
                {
                    if (ex is KerberosProtocolException kex && kex?.Error?.ErrorCode == KerberosErrorCode.KRB_AP_ERR_TKT_EXPIRED)
                    {
                        await this.PurgeTickets();
                        await client.GetServiceTicket(this.ServicePrincipalName);
                        break;
                    }

                    this.WriteLine(ex?.Message ?? SR.Resource("Unknown Error"));
                }
            }

            if (this.Verbose)
            {
                this.WriteLine();
            }
        }

        private void ListTickets(string cache)
        {
            TicketCacheBase.TryParseCacheType(cache, out _, out string path);

            var ticketCache = new Krb5TicketCache(path);

            var tickets = ticketCache.Krb5Cache.Credentials.ToArray();

            this.WriteLine(string.Format("{0}: {{TicketCount}}", SR.Resource("CommandLine_KList_Count")), tickets.Length);
            this.WriteLine();

            for (var i = 0; i < tickets.Length; i++)
            {
                var ticket = tickets[i];

                KrbTicket decodedTicket = TryParseTicket(ticket.Ticket);

                var properties = new List<(string, (string, object[]))>
                {
                    (SR.Resource("CommandLine_KList_Client"), ("{CName} @ {Realm}", new[] { ticket.Client.FullyQualifiedName, ticket.Client.Realm })),
                    (SR.Resource("CommandLine_KList_Server"), ("{SName} @ {Realm}", new[] { ticket.Server.FullyQualifiedName, ticket.Server.Realm })),
                    (SR.Resource("CommandLine_KList_TicketEType"), ("{EType} ({ETypeInt})", new object[] { decodedTicket?.EncryptedPart?.EType, (int)decodedTicket?.EncryptedPart?.EType })),
                    (SR.Resource("CommandLine_KList_Flags"), ("{FlagsHex:x} -> {Flags}", new object[] { (uint)ticket.Flags, ticket.Flags })),
                    (SR.Resource("CommandLine_KList_Start"), ("{StartTime}", new object[] { ticket.AuthTime.ToLocalTime() })),
                    (SR.Resource("CommandLine_KList_End"), ("{EndTime}", new object[] { ticket.EndTime.ToLocalTime() })),
                    (SR.Resource("CommandLine_KList_RenewTime"), ("{RenewTime}", new object[] { ticket.RenewTill.ToLocalTime() }))
                };

                var ticketEntryNumber = string.Format("#{0}>", i);

                var max = properties.Max(p => p.Item1.Length) + 10;

                bool first = true;

                foreach (var prop in properties)
                {
                    var key = SR.Resource(prop.Item1).PadLeft(max - 1).PadRight(max);

                    if (first)
                    {
                        key = ticketEntryNumber + key.Substring(ticketEntryNumber.Length);

                        first = false;
                    }

                    this.WriteLine(string.Format("{0}: {1}", key, prop.Item2.Item1), prop.Item2.Item2);
                }

                if (i < tickets.Length - 1)
                {
                    this.WriteLine();
                }
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
