// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using Kerberos.NET.Client;
using Kerberos.NET.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;

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

        [CommandLineParameter("dump", Description = "Dump")]
        public string DumpServicePrincipalName { get; set; }

        [CommandLineParameter("negotiate", Description = "Negotiate")]
        public bool DumpAsNegotiate { get; set; }

        [CommandLineParameter("d|debug", Description = "DescribeClient")]
        public bool DescribeClient { get; set; }

        [CommandLineParameter("tgt", Description = "ShowTgt")]
        public bool ShowTgt { get; set; }

        [CommandLineParameter("renew", Description = "RenewTicket")]
        public bool RenewTgt { get; set; }

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

            if (!string.IsNullOrWhiteSpace(this.DumpServicePrincipalName))
            {
                await this.DumpServiceTicket(client);
            }

            if (this.RenewTgt)
            {
                await this.RenewServiceTicket(client);
            }

            this.ListTickets(client);

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

        private async Task RenewServiceTicket(KerberosClient client)
        {
            await ExecuteWithErrorHandling(
                client,
                async c => await c.RenewTicket()
            );
        }

        private async Task DumpServiceTicket(KerberosClient client)
        {
            var rep = await client.GetServiceTicket(this.DumpServicePrincipalName);

            string apreq;

            if (this.DumpAsNegotiate)
            {
                apreq = Convert.ToBase64String(rep.EncodeGssApi().ToArray());
            }
            else
            {
                apreq = Convert.ToBase64String(rep.EncodeApplication().ToArray());
            }

            var command = new KerberosDumpCommand(CommandLineParameters.Parse($"kdecode --ticket \"{apreq}\""));

            await command.Execute();
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

        private async Task ExecuteWithErrorHandling(KerberosClient client, Func<KerberosClient, Task> function)
        {
            try
            {
                await function(client);
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

        private async Task GetServiceTicket(KerberosClient client)
        {
            await ExecuteWithErrorHandling(
                client,
                async c => await c.GetServiceTicket(this.ServicePrincipalName)
            );
        }

        private void ListTickets(KerberosClient client)
        {
            IEnumerable<KerberosClientCacheEntry> cache;

            if (client.Cache is ITicketCache2 cache2)
            {
                cache = cache2.GetAll().Cast<KerberosClientCacheEntry>();
            }
            else
            {
                cache = Array.Empty<KerberosClientCacheEntry>();
            }

            var tickets = cache.Where(c => c.EndTime > DateTimeOffset.UtcNow).ToArray();

            this.WriteLine(string.Format("{0}: {{TicketCount}}", SR.Resource("CommandLine_KList_Count")), tickets.Length);
            this.WriteLine();

            for (var i = 0; i < tickets.Length; i++)
            {
                var ticket = tickets[i];

                KrbTicket decodedTicket = ticket.KdcResponse.Ticket;

                var properties = new List<(string, (string, object[]))>
                {
                    (SR.Resource("CommandLine_KList_Client"), ("{CName} @ {Realm}", new[] { ticket.KdcResponse.CName.FullyQualifiedName, ticket.KdcResponse.CRealm })),
                    (SR.Resource("CommandLine_KList_Server"), ("{SName} @ {Realm}", new[] { ticket.SName.FullyQualifiedName, ticket.KdcResponse.Ticket.Realm })),
                    (SR.Resource("CommandLine_KList_TicketEType"), ("{EType} ({ETypeInt})", new object[] { decodedTicket?.EncryptedPart?.EType, (int)decodedTicket?.EncryptedPart?.EType })),
                    (SR.Resource("CommandLine_KList_Flags"), ("{FlagsHex:x} -> {Flags}", new object[] { (uint)ticket.Flags, ticket.Flags })),
                    (SR.Resource("CommandLine_KList_Start"), ("{StartTime}", new object[] { ticket.AuthTime.ToLocalTime() })),
                    (SR.Resource("CommandLine_KList_End"), ("{EndTime}", new object[] { ticket.EndTime.ToLocalTime() })),
                    (SR.Resource("CommandLine_KList_RenewTime"), ("{RenewTime}", new object[] { ticket.RenewTill?.ToLocalTime() })),
                };

                if (ticket.SessionKey != null)
                {
                    properties.Add((SR.Resource("CommandLine_KList_SessionEType"), ("{EType} ({ETypeInt})", new object[] { ticket.SessionKey.EType, (int)ticket.SessionKey.EType })));
                }

                if (ticket.BranchId > 0)
                {
                    properties.Add((SR.Resource("CommandLine_KList_BranchId"), ("{BranchHex:x} -> {Branch}", new object[] { (uint)ticket.Flags, ticket.Flags })));
                }

                if (!string.IsNullOrWhiteSpace(ticket.KdcCalled))
                {
                    properties.Add((SR.Resource("CommandLine_KList_KdcCalled"), ("{Kdc}", new object[] { ticket.KdcCalled })));
                }

                var ticketEntryNumber = string.Format("#{0}>", i);

                var max = properties.Max(p => p.Item1.Length) + 10;

                bool first = true;

                foreach (var prop in properties)
                {
                    var key = SR.Resource(prop.Item1).PadLeft(max - 1).PadRight(max);

                    if (first)
                    {
                        key = ticketEntryNumber + key[ticketEntryNumber.Length..];

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
