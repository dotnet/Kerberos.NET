// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Kerberos.NET.Client;
using Microsoft.Extensions.Logging;

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

        [CommandLineParameter("verbose", Description = "Verbose")]
        public bool Verbose { get; protected set; }

        public override async Task<bool> Execute()
        {
            if (await base.Execute())
            {
                return true;
            }

            var client = this.CreateClient(verbose: this.Verbose);

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

            var myTgt = myTgtEntry.KdcResponse?.Ticket;

            if (myTgt == null)
            {
                this.WriteHeader(SR.Resource("CommandLine_WhoAmI_NoTgt"));
                return;
            }

            var result = await client.GetServiceTicket(
                new RequestServiceTicket
                {
                    ServicePrincipalName = client.UserPrincipalName,
                    UserToUserTicket = myTgt,
                    CacheTicket = false,
                }
            );

            var authenticator = new KerberosAuthenticator(new KerberosValidator(myTgtEntry.SessionKey.AsKey()));

            var identity = await authenticator.Authenticate(result.ApReq.EncodeApplication());

            this.DescribeTicket(identity as KerberosIdentity);
        }

        private void DescribeTicket(KerberosIdentity identity)
        {
            this.WriteLine();

            var properties = new List<(string, string)>
            {
                ("CommandLine_WhoAmI_UserName", $"{identity.Name}"),
            };

            var groups = new List<Claim>();
            var others = new List<Claim>();

            foreach (var claim in identity.Claims)
            {
                if (claim.Type == ClaimTypes.Role)
                {
                    continue;
                }
                else if (claim.Type == ClaimTypes.GroupSid)
                {
                    groups.Add(claim);
                }
                else
                {
                    others.Add(claim);
                }
            }

            properties.Add(("", SR.Resource("CommandLine_WhoAmI_Claims")));

            foreach (var claim in others)
            {
                properties.Add((CollapseSchemaUrl(claim.Type), claim.Value));
            }

            properties.Add(("", SR.Resource("CommandLine_WhoAmI_Groups")));

            foreach (var group in groups.OrderBy(c => c.Value.Length))
            {
                properties.Add((group.Value, ""));
            }

            var max = properties.Where(p => !string.IsNullOrWhiteSpace(p.Item2)).Max(p => p.Item1.Length);

            if (max > 50)
            {
                max = 50;
            }

            foreach (var prop in properties)
            {
                if (string.IsNullOrWhiteSpace(prop.Item1))
                {
                    this.WriteLine();
                    this.WriteHeader(prop.Item2);
                    this.WriteLine();
                    continue;
                }

                string key;

                if (string.IsNullOrWhiteSpace(prop.Item2))
                {
                    key = SR.Resource(prop.Item1);
                }
                else
                {
                    key = string.Format("{0}: ", SR.Resource(prop.Item1).PadLeft(max));
                }

                this.WriteLine(string.Format("  {0}{{Value}}", key), prop.Item2);
            }

            this.WriteLine();
        }

        private static string CollapseSchemaUrl(string url)
        {
            var knownSchemas = new[]
            {
                "http://schemas.microsoft.com/identity/claims/",
                "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/"
            };

            var textInfo = CultureInfo.CurrentCulture.TextInfo;

            foreach (var schema in knownSchemas)
            {
                if (url.StartsWith(schema))
                {
                    return textInfo.ToTitleCase(url.Substring(schema.Length));
                }
            }

            return url;
        }
    }
}
